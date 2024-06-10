from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _
from utilities.forms.rendering import FieldSet

from netbox.forms import NetBoxModelFilterSetForm
from utilities.forms.fields import (
    ContentTypeMultipleChoiceField,
    DynamicModelMultipleChoiceField,
    TagFilterField,
)
from ..constants import *
from ..models import Secret, SecretRole

__all__ = [
    'SecretRoleFilterForm',
    'SecretFilterForm',
]


class SecretRoleFilterForm(NetBoxModelFilterSetForm):
    model = SecretRole
    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('id', name='Secret Role'),
    )
    id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Roles Name'))
    tag = TagFilterField(model)


class SecretFilterForm(NetBoxModelFilterSetForm):
    model = Secret

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),     
        FieldSet('id', name='Secret'),
        FieldSet('role_id', 'assigned_object_type_id', name="Attributes"),
    )

    id = DynamicModelMultipleChoiceField(queryset=Secret.objects.all(), required=False, label=_('Name'))
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label='Object type(s)',
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))
    tag = TagFilterField(model)
