from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _
from netbox.forms import (
    NetBoxModelBulkEditForm,
    NetBoxModelFilterSetForm,
    NetBoxModelForm,
    NetBoxModelImportForm,
)
from utilities.forms import (
    ContentTypeMultipleChoiceField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
    SlugField,
    SmallTextarea,
)

from netbox_secrets.constants import *
from netbox_secrets.models import Secret, SecretRole, UserKey


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


#
# Secret roles
#


class SecretRoleForm(NetBoxModelForm):
    slug = SlugField()

    class Meta:
        model = SecretRole
        fields = ('name', 'slug', 'description')


class SecretRoleImportForm(NetBoxModelImportForm):
    slug = SlugField()

    class Meta:
        model = SecretRole
        fields = ('name', 'slug')


class SecretRoleBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(queryset=SecretRole.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(max_length=200, required=False)

    model = SecretRole

    class Meta:
        nullable_fields = ['description']


class SecretRoleFilterForm(NetBoxModelFilterSetForm):
    model = SecretRole
    q = forms.CharField(required=False, label=_('Search'))
    name = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False)


#
# Secrets
#


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

    class Meta:
        model = Secret
        fields = (
            'role',
            'name',
            'plaintext',
            'plaintext2',
            'tags',
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


class SecretFilterForm(NetBoxModelFilterSetForm):
    model = Secret
    q = forms.CharField(required=False, label=_('Search'))
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label='Object type(s)',
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))


#
# UserKeys
#


class UserKeyForm(forms.ModelForm):
    public_key = forms.CharField(
        widget=SmallTextarea(
            attrs={
                'class': 'form-control',
            },
        ),
        label='Public Key (PEM format)',
        help_text='Enter your public RSA key. Keep the private one with you; you will need it for decryption. Please note that passphrase-protected keys are not supported.',
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
    _selected_action = forms.ModelMultipleChoiceField(queryset=UserKey.objects.all(), label='User Keys')
    secret_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'vLargeTextField',
            },
        ),
        label='Your private key',
    )
