import os

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import strxor
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.encoding import force_bytes

from netbox.models import NetBoxModel, PrimaryModel
from netbox.models.features import ContactsMixin
from utilities.querysets import RestrictedQuerySet
from ..constants import CENSOR_MASTER_KEY, CENSOR_MASTER_KEY_CHANGED
from ..exceptions import InvalidKey
from ..hashers import SecretValidationHasher
from ..querysets import UserKeyQuerySet
from ..utils import decrypt_master_key, encrypt_master_key, generate_random_key

__all__ = [
    'Secret',
    'SecretRole',
    'SessionKey',
    'UserKey',
]

plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets', {})


class UserKey(NetBoxModel):
    """
    A UserKey stores a user's personal RSA (public) encryption key, which is used to generate their unique encrypted
    copy of the master encryption key. The encrypted instance of the master key can be decrypted only with the user's
    matching (private) decryption key.
    """

    id = models.BigAutoField(primary_key=True)
    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_key', editable=False
    )
    public_key = models.TextField(
        verbose_name='RSA public key',
    )
    master_key_cipher = models.BinaryField(max_length=512, blank=True, null=True, editable=False)

    objects = UserKeyQuerySet.as_manager()

    class Meta:
        ordering = ['user__username']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Store the initial public_key and master_key_cipher to check for changes on save().
        self.__initial_public_key = self.public_key
        self.__initial_master_key_cipher = self.master_key_cipher

    def __str__(self):
        return self.user.username

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:userkey', args=[self.pk])

    def clean(self):
        super().clean()

        if self.public_key:
            # Validate the public key format
            try:
                pubkey = RSA.import_key(self.public_key)
            except ValueError:
                raise ValidationError({'public_key': "Invalid RSA key format."})
            except Exception:
                raise ValidationError(
                    "Something went wrong while trying to save your key. Please ensure that you're "
                    "uploading a valid RSA public key in PEM format (no SSH/PGP).",
                )

            # Validate the public key length
            pubkey_length = pubkey.size_in_bits()
            if pubkey_length < settings.PLUGINS_CONFIG['netbox_secrets']['public_key_size']:
                raise ValidationError(
                    {
                        'public_key': "Insufficient key length. Keys must be at least {} bits long.".format(
                            settings.PLUGINS_CONFIG['netbox_secrets']['public_key_size'],
                        ),
                    },
                )
            # We can't use keys bigger than our master_key_cipher field can hold
            if pubkey_length > 8192:
                raise ValidationError(
                    {
                        'public_key': "Public key size ({}) is too large. Maximum key size is 8192 bits.".format(
                            pubkey_length,
                        ),
                    },
                )

    def save(self, *args, **kwargs):
        # Check whether public_key has been modified. If so, nullify the initial master_key_cipher.
        if self.__initial_master_key_cipher and self.public_key != self.__initial_public_key:
            self.master_key_cipher = None

        # If no other active UserKeys exist, generate a new master key and use it to activate this UserKey.
        if self.is_filled() and not self.is_active() and not UserKey.objects.active().count():
            master_key = generate_random_key()
            self.master_key_cipher = encrypt_master_key(master_key, self.public_key)

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # If Secrets exist and this is the last active UserKey, prevent its deletion. Deleting the last UserKey will
        # result in the master key being destroyed and rendering all Secrets inaccessible.
        if Secret.objects.count() and [uk.pk for uk in UserKey.objects.active()] == [self.pk]:
            raise Exception(
                "Cannot delete the last active UserKey when Secrets exist! This would render all secrets "
                "inaccessible.",
            )

        super().delete(*args, **kwargs)

    def to_objectchange(self, action):
        objectchange = super().to_objectchange(action)

        # Censor any backend parameters marked as sensitive in the serialized data
        pre_change_params = {}
        post_change_params = {}
        if objectchange.prechange_data:
            pre_change_params = objectchange.prechange_data
        if objectchange.postchange_data:
            post_change_params = objectchange.postchange_data
        if post_change_params.get("master_key_cipher"):
            if post_change_params["master_key_cipher"] != pre_change_params.get("master_key_cipher"):
                # Set the "changed" master_key_cipher if the parameter's value has been modified
                post_change_params["master_key_cipher"] = CENSOR_MASTER_KEY_CHANGED
            else:
                post_change_params["master_key_cipher"] = CENSOR_MASTER_KEY
        if pre_change_params.get("master_key_cipher"):
            pre_change_params["master_key_cipher"] = CENSOR_MASTER_KEY

        return objectchange

    def is_filled(self):
        """
        Returns True if the UserKey has been filled with a public RSA key.
        """
        return bool(self.public_key)

    is_filled.boolean = True

    def is_active(self):
        """
        Returns True if the UserKey has been populated with an encrypted copy of the master key.
        """
        return self.master_key_cipher is not None

    is_active.boolean = True

    def get_master_key(self, private_key):
        """
        Given the User's private key, return the encrypted master key.
        """
        if not self.is_active:
            raise ValueError("Unable to retrieve master key: UserKey is inactive.")
        try:
            return decrypt_master_key(force_bytes(self.master_key_cipher), private_key)
        except ValueError:
            return None

    def activate(self, master_key):
        """
        Activate the UserKey by saving an encrypted copy of the master key to the database.
        """
        if not self.public_key:
            raise Exception("Cannot activate UserKey: Its public key must be filled first.")
        self.master_key_cipher = encrypt_master_key(master_key, self.public_key)
        self.save()


class SessionKey(models.Model):
    """
    A SessionKey stores a User's temporary key to be used for the encryption and decryption of secrets.
    """

    id = models.BigAutoField(primary_key=True)
    userkey = models.OneToOneField(to='UserKey', on_delete=models.CASCADE, related_name='session_key', editable=False)
    cipher = models.BinaryField(max_length=512, editable=False)
    hash = models.CharField(max_length=128, editable=False)
    created = models.DateTimeField(auto_now_add=True)

    key = None

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ['userkey__user__username']

    def __str__(self):
        return f'{self.userkey.user.username} (RSA)'

    def save(self, master_key=None, *args, **kwargs):
        if master_key is None:
            raise Exception("The master key must be provided to save a session key.")

        # Generate a random 256-bit session key if one is not already defined
        if self.key is None:
            self.key = generate_random_key()

        # Generate SHA256 hash using Django's built-in password hashing mechanism
        self.hash = make_password(self.key)

        # Encrypt master key using the session key
        self.cipher = strxor.strxor(self.key, master_key)

        super().save(*args, **kwargs)

    def get_master_key(self, session_key):
        # Validate the provided session key
        if not check_password(session_key, self.hash):
            raise InvalidKey("Invalid session key")

        # Decrypt master key using provided session key
        master_key = strxor.strxor(session_key, bytes(self.cipher))

        return master_key

    def get_session_key(self, master_key):
        # Recover session key using the master key
        session_key = strxor.strxor(master_key, bytes(self.cipher))

        # Validate the recovered session key
        if not check_password(session_key, self.hash):
            raise InvalidKey("Invalid master key")

        return session_key


class SecretRole(PrimaryModel):
    """
    A SecretRole represents an arbitrary functional classification of Secrets. For example, a user might define roles
    such as "Login Credentials" or "SNMP Communities."
    """

    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)

    clone_fields = ['tags']

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:secretrole', args=[self.pk])


class Secret(PrimaryModel, ContactsMixin):
    """
    A Secret stores an AES256-encrypted copy of sensitive data, such as passwords or secret keys. An irreversible
    SHA-256 hash is stored along with the ciphertext for validation upon decryption. Each Secret is assigned to exactly
    one NetBox object, and objects may have multiple Secrets associated with them. A name can optionally be defined
    along with the ciphertext; this string is stored as plain text in the database.

    A Secret can be up to 65,535 bytes (64KB - 1B) in length. Each secret string will be padded with random data to
    a minimum of 64 bytes during encryption in order to protect short strings from ciphertext analysis.
    """

    assigned_object_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.PROTECT,
        related_name='secrets',
    )
    assigned_object_id = models.PositiveIntegerField()
    # Internal field for searching the assinged object
    _object_repr = models.CharField(max_length=200, editable=False, blank=True, null=True)
    assigned_object = GenericForeignKey(ct_field='assigned_object_type', fk_field='assigned_object_id')
    role = models.ForeignKey(to='SecretRole', on_delete=models.PROTECT, related_name='secrets')
    name = models.CharField(max_length=100, blank=True)
    ciphertext = models.BinaryField(
        max_length=65568,
        editable=False,  # 128-bit IV + 16-bit pad length + 65535B secret + 15B padding
    )
    hash = models.CharField(max_length=128, editable=False)

    objects = RestrictedQuerySet.as_manager()

    plaintext = None

    clone_fields = ('role', 'assigned_object_id', 'assigned_object_type', 'tags')

    prerequisite_models = ('netbox_secrets.SecretRole', *plugin_settings.get('apps'))

    class Meta:
        ordering = ('role', 'name', 'pk')
        unique_together = ('assigned_object_type', 'assigned_object_id', 'role', 'name')

    def __init__(self, *args, **kwargs):
        self.plaintext = kwargs.pop('plaintext', None)
        super().__init__(*args, **kwargs)

    def __str__(self):
        return self.name or 'Secret'

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:secret', args=[self.pk])

    def save(self, *args, **kwargs):
        self._object_repr = str(self.assigned_object)

        return super().save(*args, **kwargs)

    def _pad(self, s):
        """
        Prepend the length of the plaintext (2B) and pad with garbage to a multiple of 16B (minimum of 64B).
        +--+--------+-------------------------------------------+
        |LL|MySecret|xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
        +--+--------+-------------------------------------------+
        """
        s = s.encode('utf8')
        if len(s) > 65535:
            raise ValueError("Maximum plaintext size is 65535 bytes.")

        # Minimum ciphertext size is 64 bytes to conceal the length of short secrets.
        if len(s) <= 62:
            pad_length = 62 - len(s)
        elif (len(s) + 2) % 16:
            pad_length = 16 - ((len(s) + 2) % 16)
        else:
            pad_length = 0

        header = bytes([len(s) >> 8]) + bytes([len(s) % 256])

        return header + s + os.urandom(pad_length)

    def _unpad(self, s):
        """
        Consume the first two bytes of s as a plaintext length indicator and return only that many bytes as the
        plaintext.
        """
        if isinstance(s[0], str):
            plaintext_length = (ord(s[0]) << 8) + ord(s[1])
        else:
            plaintext_length = (s[0] << 8) + s[1]
        return s[2 : plaintext_length + 2].decode('utf8')

    def encrypt(self, secret_key):
        """
        Generate a random initialization vector (IV) for AES. Pad the plaintext to the AES block size (16 bytes) and
        encrypt. Prepend the IV for use in decryption. Finally, record the SHA256 hash of the plaintext for validation
        upon decryption.
        """
        if self.plaintext is None:
            raise Exception("Must unlock or set plaintext before locking.")

        # Pad and encrypt plaintext
        iv = os.urandom(16)
        aes = AES.new(secret_key, AES.MODE_CFB, iv)
        self.ciphertext = iv + aes.encrypt(self._pad(self.plaintext))

        # Generate SHA256 using Django's built-in password hashing mechanism
        self.hash = make_password(self.plaintext, hasher=SecretValidationHasher())

        self.plaintext = None

    def decrypt(self, secret_key):
        """
        Consume the first 16 bytes of self.ciphertext as the AES initialization vector (IV). The remainder is decrypted
        using the IV and the provided secret key. Padding is then removed to reveal the plaintext. Finally, validate the
        decrypted plaintext value against the stored hash.
        """
        if self.plaintext is not None:
            return
        if not self.ciphertext:
            raise Exception("Must define ciphertext before unlocking.")

        # Decrypt ciphertext and remove padding
        iv = bytes(self.ciphertext[0:16])
        ciphertext = bytes(self.ciphertext[16:])
        aes = AES.new(secret_key, AES.MODE_CFB, iv)
        plaintext = self._unpad(aes.decrypt(ciphertext))

        # Verify decrypted plaintext against hash
        if not self.validate(plaintext):
            raise ValueError("Invalid key or ciphertext!")

        self.plaintext = plaintext

    def validate(self, plaintext):
        """
        Validate that a given plaintext matches the stored hash.
        """
        if not self.hash:
            raise Exception("Hash has not been generated for this secret.")
        return check_password(plaintext, self.hash, preferred=SecretValidationHasher())

    @property
    def enable_contacts(self):
        return plugin_settings.get('enable_contacts', False)


if plugin_settings.get('enable_contacts', False):
    GenericRelation(
        to='tenancy.ContactAssignment',
        content_type_field='object_type',
        object_id_field='object_id',
        related_query_name='secret',
    ).contribute_to_class(Secret, 'contacts')
