from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from django import forms
from django.utils.translation import gettext as _

from netbox.forms import NetBoxModelForm
from utilities.forms.fields import CommentField, DynamicModelChoiceField, SlugField
from utilities.forms.rendering import FieldSet
from ..constants import *
from ..models import Secret, SecretRole, UserKey, TenantMembership, TenantServiceAccount, TenantSecret
from ..utils import (
    detect_key_type, validate_x25519_public_key, normalize_public_key,
    KEY_TYPE_X25519, KEY_TYPE_SSH_ED25519, NACL_AVAILABLE
)

__all__ = [
    'ActivateUserKeyForm',
    'SecretRoleForm',
    'SecretForm',
    'UserKeyForm',
    # Tenant crypto forms
    'TenantMembershipForm',
    'TenantServiceAccountForm',
    'TenantSecretForm',
]


def validate_public_key(key):
    """
    Validate the format and type of a public key (RSA, X25519, or SSH ed25519).
    """
    key_type = detect_key_type(key)

    if key_type == KEY_TYPE_X25519:
        # Validate X25519 key
        if not NACL_AVAILABLE:
            raise forms.ValidationError(
                "X25519 keys require pynacl library. Please install with: pip install pynacl"
            )
        try:
            validate_x25519_public_key(key)
        except ValueError as e:
            raise forms.ValidationError(str(e))
    elif key_type == KEY_TYPE_SSH_ED25519:
        # Validate and convert SSH ed25519 key to X25519
        if not NACL_AVAILABLE:
            raise forms.ValidationError(
                "SSH ed25519 keys require pynacl library. Please install with: pip install pynacl"
            )
        try:
            # Test conversion - this validates the key format
            normalize_public_key(key)
        except ValueError as e:
            raise forms.ValidationError(f"Invalid SSH ed25519 key: {e}")
    else:
        # Validate RSA key (legacy)
        validate_rsa_key(key, is_secret=False)


def validate_rsa_key(key, is_secret=True):
    """
    Validate the format and type of an RSA key.
    """
    if key.startswith('ssh-rsa '):
        raise forms.ValidationError(
            "OpenSSH line format is not supported. Please ensure that your public is in PEM (base64) format.",
        )
    try:
        key = RSA.importKey(key)
    except ValueError:
        raise forms.ValidationError("Invalid RSA key. Please ensure that your key is in PEM (base64) format.")
    except Exception as e:
        raise forms.ValidationError(f"Invalid key detected: {e}")
    if is_secret and not key.has_private():
        raise forms.ValidationError("This looks like a public key. Please provide your private RSA key.")
    elif not is_secret and key.has_private():
        raise forms.ValidationError("This looks like a private key. Please provide your public RSA key.")
    try:
        PKCS1_OAEP.new(key)
    except Exception:
        raise forms.ValidationError("Error validating RSA key. Please ensure that your key supports PKCS#1 OAEP.")


class SecretRoleForm(NetBoxModelForm):
    slug = SlugField()

    fieldsets = (FieldSet('name', 'slug', 'description', 'tags', name=None),)

    class Meta:
        model = SecretRole
        fields = ('name', 'slug', 'description', 'comments', 'tags')


class SecretForm(NetBoxModelForm):
    plaintext = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label='Plaintext',
        widget=forms.PasswordInput(
            attrs={
                'class': 'requires-session-key',
                'autocomplete': 'new-password',
            },
        ),
    )
    plaintext2 = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label='Plaintext (verify)',
        widget=forms.PasswordInput(
            attrs={
                'autocomplete': 'new-password',
            },
        ),
    )
    totp_plaintext = forms.CharField(
        max_length=128,
        required=False,
        label='TOTP Seed',
        help_text='Base32-encoded TOTP secret (e.g., from authenticator app setup). Leave blank if not using 2FA.',
        widget=forms.TextInput(
            attrs={
                'class': 'requires-session-key',
                'autocomplete': 'off',
            },
        ),
    )
    totp_plaintext2 = forms.CharField(
        max_length=128,
        required=False,
        label='TOTP Seed (verify)',
        widget=forms.TextInput(
            attrs={
                'autocomplete': 'off',
            },
        ),
    )
    role = DynamicModelChoiceField(queryset=SecretRole.objects.all())

    comments = CommentField()

    fieldsets = (
        FieldSet('name', 'description', 'role', 'tags', name=None),
        FieldSet('plaintext', 'plaintext2', name=_('Secret Data')),
        FieldSet('totp_plaintext', 'totp_plaintext2', 'totp_issuer', 'totp_digits', 'totp_period', name=_('TOTP (2FA)')),
    )

    class Meta:
        model = Secret
        fields = (
            'role',
            'name',
            'plaintext',
            'plaintext2',
            'totp_plaintext',
            'totp_plaintext2',
            'totp_issuer',
            'totp_digits',
            'totp_period',
            'tags',
            'description',
            'comments',
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # A plaintext value is required when creating a new Secret
        if not self.instance.pk:
            self.fields['plaintext'].required = True

    def clean(self):
        super().clean()

        # Verify that the provided plaintext values match
        if self.cleaned_data['plaintext'] != self.cleaned_data['plaintext2']:
            raise forms.ValidationError(
                {'plaintext2': "The two given plaintext values do not match. Please check your input."},
            )

        # Verify that the provided TOTP values match
        totp = self.cleaned_data.get('totp_plaintext', '')
        totp2 = self.cleaned_data.get('totp_plaintext2', '')
        if totp != totp2:
            raise forms.ValidationError(
                {'totp_plaintext2': "The two given TOTP seed values do not match. Please check your input."},
            )

        # Validate TOTP seed format (base32)
        if totp:
            import re
            # Base32 uses A-Z and 2-7, optionally with = padding
            if not re.match(r'^[A-Z2-7]+=*$', totp.upper()):
                raise forms.ValidationError(
                    {'totp_plaintext': "Invalid TOTP seed format. Must be a valid Base32-encoded string."},
                )


class UserKeyForm(forms.ModelForm):
    public_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control',
            },
        ),
        label='Public Key',
        help_text='Enter your public key (RSA PEM, X25519 PEM, or SSH ed25519 format). '
        'SSH ed25519 keys (ssh-ed25519 AAAA...) are automatically converted to X25519. '
        'Keep the private key with you; you will need it for decryption. '
        'Passphrase-protected keys are not supported.',
    )

    class Meta:
        model = UserKey
        fields = ['public_key']

    def clean_public_key(self):
        key = self.cleaned_data['public_key']

        # Validate the public key format (RSA, X25519, or SSH ed25519).
        validate_public_key(key)

        # Normalize to internal format (converts SSH ed25519 to X25519)
        return normalize_public_key(key)


class ActivateUserKeyForm(forms.Form):
    user_keys = forms.ModelMultipleChoiceField(
        queryset=UserKey.objects.filter(master_key_cipher__isnull=True), label='User Keys'
    )
    secret_key = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'vLargeTextField'}),
        label='Your Private Key',
    )


#
# Tenant Crypto Forms
#


class TenantMembershipForm(NetBoxModelForm):
    """
    Form for viewing/editing TenantMembership.
    Note: The actual cryptographic setup happens via JavaScript/API, this is for admin management.
    """
    fieldsets = (
        FieldSet('tenant', 'user', 'role', name=_('Membership')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = TenantMembership
        fields = ['tenant', 'user', 'role', 'tags']
        widgets = {
            'tenant': forms.Select(attrs={'disabled': 'disabled'}),
            'user': forms.Select(attrs={'disabled': 'disabled'}),
        }


class TenantServiceAccountForm(NetBoxModelForm):
    """
    Form for editing TenantServiceAccount metadata.
    Note: The cryptographic setup happens via JavaScript/API.
    """
    fieldsets = (
        FieldSet('name', 'tenant', 'description', 'enabled', name=_('Service Account')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = TenantServiceAccount
        fields = ['name', 'tenant', 'description', 'enabled', 'tags']
        widgets = {
            'tenant': forms.Select(attrs={'disabled': 'disabled'}),
        }


class TenantSecretForm(NetBoxModelForm):
    """
    Form for viewing/editing TenantSecret metadata.
    Note: The actual secret data is encrypted client-side and managed via JavaScript/API.
    """
    fieldsets = (
        FieldSet('name', 'tenant', 'description', name=_('Secret')),
        FieldSet('totp_issuer', 'totp_digits', 'totp_period', name=_('TOTP Settings')),
        FieldSet('tags', name=_('Tags')),
    )

    class Meta:
        model = TenantSecret
        fields = ['name', 'tenant', 'description', 'totp_issuer', 'totp_digits', 'totp_period', 'tags']
        widgets = {
            'tenant': forms.Select(attrs={'disabled': 'disabled'}),
        }
