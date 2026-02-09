from django.utils.translation import gettext_lazy as _

from core.models import ObjectType
from netbox.forms import (
    NestedGroupModelFilterSetForm,
    PrimaryModelFilterSetForm,
)
from netbox_secrets.constants import SECRET_ASSIGNABLE_MODELS
from netbox_secrets.models import Secret, SecretRole
from tenancy.forms import ContactModelFilterForm
from utilities.forms.fields import (
    ContentTypeMultipleChoiceField,
    DynamicModelMultipleChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet

__all__ = [
    'SecretFilterForm',
    'SecretRoleFilterForm',
]


class SecretRoleFilterForm(NestedGroupModelFilterSetForm):
    model = SecretRole
    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', 'owner_id'),
        FieldSet('parent_id', name=_('Secret Role')),
    )
    parent_id = DynamicModelMultipleChoiceField(
        queryset=SecretRole.objects.all(), required=False, label=_('Parent role')
    )
    tag = TagFilterField(model)


class SecretFilterForm(ContactModelFilterForm, PrimaryModelFilterSetForm):
    model = Secret

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', 'owner_id'),
        FieldSet('role_id', name=_('Secret')),
        FieldSet('contact', 'contact_role', 'contact_group', name=_('Contacts')),
        FieldSet('assigned_object_type_id', name=_("Attributes")),
    )
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ObjectType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label=_('Object Type'),
    )
    role_id = DynamicModelMultipleChoiceField(
        queryset=SecretRole.objects.all(), required=False, null_option='None', label=_('Role')
    )
    tag = TagFilterField(model)
