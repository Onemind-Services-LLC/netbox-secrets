"""
Key management models for NetBox Secrets Plugin.

This module contains models for managing encryption keys:
- UserKey: Stores users' RSA public keys and encrypted master key copies
- SessionKey: Manages temporary session keys for secret encryption/decryption
"""

from typing import Optional

from Crypto.PublicKey import RSA
from Crypto.Util import strxor
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import ProtectedError
from django.utils.encoding import force_bytes
from django.utils.translation import gettext_lazy as _

from netbox.models import NetBoxModel
from utilities.querysets import RestrictedQuerySet
from ..constants import CENSOR_MASTER_KEY, CENSOR_MASTER_KEY_CHANGED
from ..exceptions import InvalidKey
from ..querysets import UserKeyQuerySet
from ..utils import decrypt_master_key, encrypt_master_key, generate_random_key

__all__ = [
    'UserKey',
    'SessionKey',
]


def get_plugin_settings():
    """Cache plugin settings access."""
    return settings.PLUGINS_CONFIG.get('netbox_secrets', {})


class UserKey(NetBoxModel):
    """
    Stores a user's RSA public encryption key for securing their copy of the master key.

    The master key is encrypted with the user's public key and can only be decrypted
    with their corresponding private key, ensuring end-to-end encryption.

    Attributes:
        user: The user who owns this encryption key
        public_key: RSA public key in PEM format
        master_key_cipher: Encrypted copy of the master encryption key
        created: Timestamp when the key was created
        modified: Timestamp when the key was last modified
    """

    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_key',
        editable=False,
        help_text=_("User who owns this encryption key"),
    )
    public_key = models.TextField(
        verbose_name=_('RSA public key'), help_text=_("RSA public key in PEM format (minimum 2048 bits)")
    )
    master_key_cipher = models.BinaryField(
        max_length=512, blank=True, null=True, editable=False, help_text=_("Encrypted copy of the master key")
    )

    objects = UserKeyQuerySet.as_manager()

    class Meta:
        ordering = ['user__username']
        verbose_name = _('User Key')
        verbose_name_plural = _('User Keys')
        indexes = [
            models.Index(fields=['user']),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Track initial values for change detection
        self._initial_public_key = self.public_key
        self._initial_master_key_cipher = self.master_key_cipher

    def __str__(self):
        return self.user.username

    def clean(self):
        """
        Validate the RSA public key format and size requirements.

        Raises:
            ValidationError: If the key format is invalid or doesn't meet size requirements
        """
        super().clean()

        if not self.public_key:
            return

        # Prevent changing the public key if secrets exist and this is the only active key
        if self.pk and self.public_key != self._initial_public_key:
            from .secrets import Secret  # Local import to avoid circular dependency

            if Secret.objects.exists() and not UserKey.objects.active().exclude(pk=self.pk).exists():
                raise ValidationError(
                    {
                        'public_key': _(
                            "Cannot change public key while secrets exist and this is the only active key. "
                            "Create and activate another user key first."
                        )
                    }
                )

        # Validate RSA key format
        try:
            pubkey = RSA.import_key(self.public_key)
        except ValueError as e:
            raise ValidationError({'public_key': _("Invalid RSA key format: {}").format(str(e))})
        except Exception:
            raise ValidationError(
                {
                    'public_key': _(
                        "Failed to import RSA key. Please ensure you're uploading a valid "
                        "RSA public key in PEM format (not SSH or PGP format)."
                    )
                }
            )

        # Validate key length constraints
        pubkey_length = pubkey.size_in_bits()
        min_key_size = get_plugin_settings().get('public_key_size', 2048)
        max_key_size = 8192  # Database field constraint

        if pubkey_length < min_key_size:
            raise ValidationError(
                {
                    'public_key': _("Key length ({} bits) is below minimum requirement ({} bits).").format(
                        pubkey_length, min_key_size
                    )
                }
            )

        if pubkey_length > max_key_size:
            raise ValidationError(
                {
                    'public_key': _("Key length ({} bits) exceeds maximum allowed ({} bits).").format(
                        pubkey_length, max_key_size
                    )
                }
            )

    @transaction.atomic
    def save(self, *args, **kwargs):
        """
        Save the UserKey, handling master key cipher invalidation and auto-activation.

        If the public key is changed, the master key cipher is invalidated.
        If this is the first active UserKey, it's automatically activated with a new master key.
        """
        # Invalidate master key cipher if public key changed
        if self._initial_master_key_cipher and self.public_key != self._initial_public_key:
            self.master_key_cipher = None

        # Auto-activate first UserKey with new master key
        if self.is_filled() and not self.is_active() and not UserKey.objects.active().exists():
            master_key = generate_random_key()
            self.master_key_cipher = encrypt_master_key(master_key, self.public_key)

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Delete the UserKey, preventing deletion if it's the last active key with secrets.

        Raises:
            ProtectedError: If this is the last active UserKey and secrets exist
        """
        # Import here to avoid circular dependency
        from .secrets import Secret

        active_keys = list(UserKey.objects.active().values_list('pk', flat=True))

        if Secret.objects.exists() and active_keys == [self.pk]:
            raise ProtectedError(
                _(
                    "Cannot delete the last active UserKey while secrets exist. "
                    "This would make all secrets permanently inaccessible."
                ),
                Secret.objects.all(),
            )

        return super().delete(*args, **kwargs)

    def to_objectchange(self, action):
        """
        Censor sensitive master key cipher in change logs.

        Args:
            action: The action being performed (create, update, delete)

        Returns:
            ObjectChange instance with censored sensitive data
        """
        objectchange = super().to_objectchange(action)

        for data_attr in ['prechange_data', 'postchange_data']:
            data = getattr(objectchange, data_attr, None) or {}

            if 'master_key_cipher' in data:
                # Mark as changed if value differs from previous
                if data_attr == 'postchange_data' and data.get('master_key_cipher') != (
                    objectchange.prechange_data or {}
                ).get('master_key_cipher'):
                    data['master_key_cipher'] = CENSOR_MASTER_KEY_CHANGED
                else:
                    data['master_key_cipher'] = CENSOR_MASTER_KEY

        return objectchange

    def is_filled(self) -> bool:
        """
        Check if UserKey has a public key configured.

        Returns:
            True if public key is set, False otherwise
        """
        return bool(self.public_key)

    is_filled.boolean = True

    def is_active(self) -> bool:
        """
        Check if UserKey has an encrypted master key copy.

        Returns:
            True if master key cipher is set, False otherwise
        """
        return self.master_key_cipher is not None

    is_active.boolean = True

    def get_master_key(self, private_key: bytes) -> Optional[bytes]:
        """
        Decrypt and return the master key using the user's private key.

        Args:
            private_key: User's RSA private key in PEM format

        Returns:
            Decrypted master key bytes, or None if decryption fails

        Raises:
            ValueError: If UserKey is not active
        """
        if not self.is_active():
            raise ValueError(_("Cannot retrieve master key: UserKey is not active."))

        try:
            return decrypt_master_key(force_bytes(self.master_key_cipher), private_key)
        except (ValueError, Exception):
            return None

    @transaction.atomic
    def activate(self, master_key: bytes) -> None:
        """
        Activate UserKey by encrypting and storing the master key.

        Args:
            master_key: Master encryption key to store

        Raises:
            ValueError: If public key is not configured
        """
        if not self.public_key:
            raise ValueError(_("Cannot activate UserKey: public key must be set first."))

        self.master_key_cipher = encrypt_master_key(master_key, self.public_key)
        self.save()


class SessionKey(models.Model):
    """
    Temporary session key for encrypting/decrypting secrets during a user session.

    Uses XOR encryption with the master key for fast symmetric encryption while
    maintaining security through the master key's protection. Each session key
    is unique to a user and expires when the session ends.

    Attributes:
        userkey: Reference to the user's encryption key
        cipher: XOR-encrypted master key
        hash: SHA-256 hash of session key for validation
        created: Timestamp when session key was created
    """

    userkey = models.OneToOneField(to='UserKey', on_delete=models.CASCADE, related_name='session_key', editable=False)
    cipher = models.BinaryField(max_length=512, editable=False, help_text=_("XOR-encrypted master key"))
    hash = models.CharField(max_length=128, editable=False, help_text=_("Hash of session key for validation"))
    created = models.DateTimeField(auto_now_add=True)

    # Transient attribute for the decrypted session key
    key: Optional[bytes] = None

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ['userkey__user__username']
        verbose_name = _('Session Key')
        verbose_name_plural = _('Session Keys')

    def __str__(self):
        return f"{self.userkey.user.username}'s session key"

    def save(self, master_key: bytes = None, *args, **kwargs):
        """
        Save session key with master key encryption.

        Generates a random 256-bit session key, hashes it for validation,
        and encrypts the master key using XOR for fast symmetric encryption.

        Args:
            master_key: Master encryption key (required)

        Raises:
            ValueError: If master_key is not provided
        """
        if master_key is None:
            raise ValueError(_("Master key is required to save a session key."))

        # Generate random 256-bit session key if not set
        if self.key is None:
            self.key = generate_random_key()

        # Hash session key for validation
        self.hash = make_password(self.key)

        # Encrypt master key with session key using XOR
        self.cipher = strxor.strxor(self.key, master_key)

        super().save(*args, **kwargs)

    def get_master_key(self, session_key: bytes) -> bytes:
        """
        Decrypt master key using provided session key.

        Args:
            session_key: Session key to decrypt with

        Returns:
            Decrypted master key

        Raises:
            InvalidKey: If session key is invalid
        """
        if not check_password(session_key, self.hash):
            raise InvalidKey(_("Invalid session key"))

        return strxor.strxor(session_key, bytes(self.cipher))

    def get_session_key(self, master_key: bytes) -> bytes:
        """
        Recover session key from master key.

        This is useful for retrieving the session key when you have
        the master key but not the original session key.

        Args:
            master_key: Master key to recover session key with

        Returns:
            Recovered session key

        Raises:
            InvalidKey: If master key is invalid
        """
        session_key = strxor.strxor(master_key, bytes(self.cipher))

        if not check_password(session_key, self.hash):
            raise InvalidKey(_("Invalid master key"))

        return session_key
