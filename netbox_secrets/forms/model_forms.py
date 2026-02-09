from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from django import forms
from django.forms import ValidationError
from django.utils.translation import gettext_lazy as _

from netbox.forms import NestedGroupModelForm, PrimaryModelForm
from utilities.forms.fields import DynamicModelChoiceField
from utilities.forms.rendering import FieldSet
from ..constants import *
from ..models import Secret, SecretRole, UserKey

__all__ = [
    'ActivateUserKeyForm',
    'SecretRoleForm',
    'SecretForm',
    'UserKeyForm',
]


def validate_rsa_key(key, is_secret=True):
    """
    Validate the format and type of an RSA key.

    Args:
        key: RSA key string to validate
        is_secret: True if validating a private key, False for public key

    Raises:
        ValidationError: If the key is invalid or of wrong type
    """
    if not key or not isinstance(key, str):
        raise ValidationError(_("Key must be a non-empty string."))

    key = key.strip()

    # Check for unsupported OpenSSH format
    if key.startswith('ssh-rsa ') or key.startswith('ssh-ed25519 '):
        raise ValidationError(
            _("OpenSSH line format is not supported. Please ensure that your key " "is in PEM (base64) format.")
        )

    # Import and validate the key
    try:
        rsa_key = RSA.importKey(key)
    except ValueError as e:
        raise ValidationError(
            _("Invalid RSA key. Please ensure that your key is in PEM (base64) format. " "Error: {error}").format(
                error=str(e)
            )
        )
    except Exception as e:
        raise ValidationError(_("Invalid key detected: {error}").format(error=str(e)))

    # Validate key size (minimum 2048 bits recommended)
    key_size = rsa_key.size_in_bits()
    if key_size < 2048:
        raise ValidationError(
            _("RSA key size must be at least 2048 bits for security. " "Your key is {size} bits.").format(size=key_size)
        )

    # Check if key type matches expectation
    if is_secret and not rsa_key.has_private():
        raise ValidationError(_("This appears to be a public key. Please provide your private RSA key."))
    elif not is_secret and rsa_key.has_private():
        raise ValidationError(_("This appears to be a private key. Please provide your public RSA key."))

    # Validate PKCS#1 OAEP compatibility
    try:
        PKCS1_OAEP.new(rsa_key)
    except Exception as e:
        raise ValidationError(
            _("Error validating RSA key. Please ensure that your key supports " "PKCS#1 OAEP. Error: {error}").format(
                error=str(e)
            )
        )

    return rsa_key


class SecretRoleForm(NestedGroupModelForm):
    parent = DynamicModelChoiceField(label=_('Parent'), queryset=SecretRole.objects.all(), required=False)

    fieldsets = (FieldSet('parent', 'name', 'slug', 'description', 'tags', name=_('Secret Role')),)

    class Meta:
        model = SecretRole
        fields = [
            'parent',
            'name',
            'slug',
            'description',
            'owner',
            'comments',
            'tags',
        ]


class SecretForm(PrimaryModelForm):
    plaintext = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label=_('Plaintext'),
        help_text=_('Enter the secret value. This will be encrypted before storage.'),
        widget=forms.PasswordInput(
            attrs={
                'class': 'requires-session-key form-control',
                'autocomplete': 'new-password',
                'placeholder': _('Enter secret value'),
            },
        ),
    )
    plaintext2 = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label=_('Plaintext (verify)'),
        help_text=_('Re-enter the secret value to confirm.'),
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'autocomplete': 'new-password',
                'placeholder': _('Re-enter secret value'),
            },
        ),
    )
    role = DynamicModelChoiceField(
        label=_('Role'),
        queryset=SecretRole.objects.all(),
    )

    fieldsets = (
        FieldSet('name', 'role', 'description', 'tags'),
        FieldSet('plaintext', 'plaintext2', name=_('Secret Data')),
    )

    class Meta:
        model = Secret
        fields = (
            'name',
            'role',
            'plaintext',
            'plaintext2',
            'description',
            'owner',
            'comments',
            'tags',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Plaintext is required when creating a new Secret
        if not self.instance.pk:
            self.fields['plaintext'].required = True
            self.fields['plaintext2'].required = True

    def clean_plaintext(self):
        """Validate plaintext field."""
        plaintext = self.cleaned_data.get('plaintext', '')

        # Check for minimum length on new secrets
        if not self.instance.pk and len(plaintext.strip()) < 1:
            raise ValidationError(_("Secret value cannot be empty."))

        return plaintext

    def clean(self):
        """Validate that plaintext values match."""
        super().clean()

        plaintext = self.cleaned_data.get('plaintext', '')
        plaintext2 = self.cleaned_data.get('plaintext2', '')

        # Verify that the provided plaintext values match
        if plaintext != plaintext2:
            raise ValidationError({'plaintext2': _("The two secret values do not match. Please check your input.")})

        return self.cleaned_data


class UserKeyForm(forms.ModelForm):
    """Form for users to submit their public RSA key for secret decryption."""

    public_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control font-monospace',
                'rows': 10,
                'placeholder': '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
            },
        ),
        label=_('Public Key'),
        help_text=_(
            'Enter your public RSA key in PEM format. Keep your private key secure; '
            'you will need it for decryption. Passphrase-protected keys are not supported. '
            'Minimum key size: 2048 bits.'
        ),
    )

    class Meta:
        model = UserKey
        fields = ['public_key']

    def clean_public_key(self):
        """Validate and clean the public key."""
        key = self.cleaned_data.get('public_key', '').strip()

        if not key:
            raise ValidationError(_("Public key is required."))

        # Validate the RSA key format and return the validated key object
        try:
            validate_rsa_key(key, is_secret=False)
        except ValidationError:
            raise

        return key


class ActivateUserKeyForm(forms.Form):
    """Form for activating user keys with a master private key."""

    user_keys = forms.ModelMultipleChoiceField(
        queryset=UserKey.objects.filter(master_key_cipher__isnull=True),
        label=_('User Keys'),
        help_text=_('Select the user keys to activate with your master private key.'),
    )
    secret_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control font-monospace',
                'rows': 15,
                'placeholder': '-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----',
            }
        ),
        label=_('Your Private Key'),
        help_text=_(
            'Enter your private RSA key in PEM format to activate the selected user keys. '
            'This key will not be stored.'
        ),
    )

    def clean_secret_key(self):
        """Validate the private key."""
        key = self.cleaned_data.get('secret_key', '').strip()

        if not key:
            raise ValidationError(_("Private key is required."))

        # Validate the RSA key format
        try:
            validate_rsa_key(key, is_secret=True)
        except ValidationError:
            raise

        return key
