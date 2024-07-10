from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from django import forms
from django.utils.translation import gettext as _

from netbox.forms import NetBoxModelForm
from utilities.forms.fields import CommentField, DynamicModelChoiceField, SlugField
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
    role = DynamicModelChoiceField(queryset=SecretRole.objects.all())

    comments = CommentField()

    fieldsets = (
        FieldSet('name', 'description', 'role', 'tags', name=None),
        FieldSet('plaintext', 'plaintext2', name=_('Secret Data')),
    )

    class Meta:
        model = Secret
        fields = (
            'role',
            'name',
            'plaintext',
            'plaintext2',
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


class UserKeyForm(forms.ModelForm):
    public_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control',
            },
        ),
        label='Public Key (PEM format)',
        help_text='Enter your public RSA key. Keep the private one with you; you will need it for decryption. Please '
        'note that passphrase-protected keys are not supported.',
    )

    class Meta:
        model = UserKey
        fields = ['public_key']

    def clean_public_key(self):
        key = self.cleaned_data['public_key']

        # Validate the RSA key format.
        validate_rsa_key(key, is_secret=False)

        return key


class ActivateUserKeyForm(forms.Form):
    user_keys = forms.ModelMultipleChoiceField(
        queryset=UserKey.objects.filter(master_key_cipher__isnull=True), label='User Keys'
    )
    secret_key = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'vLargeTextField'}),
        label='Your Private Key',
    )
