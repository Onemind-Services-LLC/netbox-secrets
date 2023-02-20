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
    TagFilterField,
)

from ..constants import *
from ..models import Secret, SecretRole, UserKey

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
    name = DynamicModelMultipleChoiceField(queryset=Secret.objects.all(), required=False)
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label='Object type(s)',
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))

    tag = TagFilterField(model)


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
