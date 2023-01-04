from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from django import forms
from django.utils.translation import gettext as _

from dcim.models import Device
from netbox.forms import NetBoxModelBulkEditForm, NetBoxModelFilterSetForm, NetBoxModelForm, NetBoxModelImportForm
from netbox_secrets.constants import *
from netbox_secrets.models import Secret, SecretRole, UserKey
from utilities.forms import CSVModelChoiceField, DynamicModelChoiceField, DynamicModelMultipleChoiceField, SlugField
from virtualization.models import VirtualMachine


def validate_rsa_key(key, is_secret=True):
    """
    Validate the format and type of an RSA key.
    """
    if key.startswith('ssh-rsa '):
        raise forms.ValidationError(
            "OpenSSH line format is not supported. Please ensure that your public is in PEM (base64) format.")
    try:
        key = RSA.importKey(key)
    except ValueError:
        raise forms.ValidationError("Invalid RSA key. Please ensure that your key is in PEM (base64) format.")
    except Exception as e:
        raise forms.ValidationError("Invalid key detected: {}".format(e))
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
    pk = forms.ModelMultipleChoiceField(
        queryset=SecretRole.objects.all(),
        widget=forms.MultipleHiddenInput
    )
    description = forms.CharField(
        max_length=200,
        required=False
    )

    model = SecretRole

    class Meta:
        nullable_fields = ['description']


class SecretRoleFilterForm(NetBoxModelFilterSetForm):
    model = SecretRole
    q = forms.CharField(
        required=False,
        label=_('Search')
    )
    name = DynamicModelMultipleChoiceField(
        queryset=SecretRole.objects.all(),
        required=False
    )


#
# Secrets
#

class SecretForm(NetBoxModelForm):
    device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False
    )
    virtual_machine = DynamicModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False
    )
    plaintext = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label='Plaintext',
        widget=forms.PasswordInput(
            attrs={
                'class': 'requires-session-key',
            }
        )
    )
    plaintext2 = forms.CharField(
        max_length=SECRET_PLAINTEXT_MAX_LENGTH,
        required=False,
        label='Plaintext (verify)',
        widget=forms.PasswordInput()
    )
    role = DynamicModelChoiceField(
        queryset=SecretRole.objects.all()
    )

    class Meta:
        model = Secret
        fields = (
            'device', 'virtual_machine', 'role', 'name', 'plaintext', 'plaintext2', 'tags',
        )

    def __init__(self, *args, **kwargs):

        # Initialize helper selectors
        instance = kwargs.get('instance')
        initial = kwargs.get('initial', {}).copy()
        if instance:
            if type(instance.assigned_object) is Device:
                initial['device'] = instance.assigned_object
            elif type(instance.assigned_object) is VirtualMachine:
                initial['virtual_machine'] = instance.assigned_object
        kwargs['initial'] = initial

        super().__init__(*args, **kwargs)

        # A plaintext value is required when creating a new Secret
        if not self.instance.pk:
            self.fields['plaintext'].required = True

    def clean(self):
        super().clean()

        if not self.cleaned_data['device'] and not self.cleaned_data['virtual_machine']:
            raise forms.ValidationError("Secrets must be assigned to a device or virtual machine.")

        if self.cleaned_data['device'] and self.cleaned_data['virtual_machine']:
            raise forms.ValidationError("Cannot select both a device and virtual machine for secret assignment.")

        # Verify that the provided plaintext values match
        if self.cleaned_data['plaintext'] != self.cleaned_data['plaintext2']:
            raise forms.ValidationError({
                'plaintext2': "The two given plaintext values do not match. Please check your input."
            })

    def save(self, *args, **kwargs):
        # Set assigned object
        self.instance.assigned_object = self.cleaned_data.get('device') or self.cleaned_data.get('virtual_machine')

        return super().save(*args, **kwargs)


class SecretImportForm(NetBoxModelImportForm):
    role = CSVModelChoiceField(
        queryset=SecretRole.objects.all(),
        to_field_name='name',
        help_text='Assigned role'
    )
    device = CSVModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        to_field_name='name',
        help_text='Assigned device'
    )
    virtual_machine = CSVModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False,
        to_field_name='name',
        help_text='Assigned VM'
    )
    plaintext = forms.CharField(
        help_text='Plaintext secret data'
    )

    class Meta:
        model = Secret
        fields = ('role', 'name', 'plaintext', 'device', 'virtual_machine')
        help_texts = {
            'name': 'Name or username',
        }

    def clean(self):
        super().clean()

        device = self.cleaned_data.get('device')
        virtual_machine = self.cleaned_data.get('virtual_machine')

        # Validate device OR VM is assigned
        if not device and not virtual_machine:
            raise forms.ValidationError("Secret must be assigned to a device or a virtual machine")
        if device and virtual_machine:
            raise forms.ValidationError("Secret cannot be assigned to both a device and a virtual machine")

    def save(self, *args, **kwargs):

        # Set device/VM assignment
        self.instance.assigned_object = self.cleaned_data['device'] or self.cleaned_data['virtual_machine']

        s = super().save(*args, **kwargs)

        # Set plaintext on instance
        s.plaintext = str(self.cleaned_data['plaintext'])

        return s


class SecretBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=Secret.objects.all(),
        widget=forms.MultipleHiddenInput()
    )
    role = DynamicModelChoiceField(
        queryset=SecretRole.objects.all(),
        required=False
    )
    name = forms.CharField(
        max_length=100,
        required=False
    )

    model = Secret

    class Meta:
        nullable_fields = [
            'name',
        ]


class SecretFilterForm(NetBoxModelFilterSetForm):
    model = Secret
    q = forms.CharField(
        required=False,
        label=_('Search')
    )
    name = DynamicModelMultipleChoiceField(
        queryset=Secret.objects.all(),
        required=False
    )
    role_id = DynamicModelMultipleChoiceField(
        queryset=SecretRole.objects.all(),
        required=False,
        label=_('Role')
    )
    device = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        required=False
    )

    virtual_machine = DynamicModelMultipleChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False
    )


#
# UserKeys
#

class UserKeyForm(forms.ModelForm):
    class Meta:
        model = UserKey
        fields = ['public_key']
        labels = {
            'public_key': ''
        }

    def clean_public_key(self):
        key = self.cleaned_data['public_key']

        # Validate the RSA key format.
        validate_rsa_key(key, is_secret=False)

        return key


class ActivateUserKeyForm(forms.Form):
    _selected_action = forms.ModelMultipleChoiceField(
        queryset=UserKey.objects.all(),
        label='User Keys'
    )
    secret_key = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'vLargeTextField',
            }
        ),
        label='Your private key'
    )
