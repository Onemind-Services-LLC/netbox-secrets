from django.utils.translation import gettext_lazy as _

from netbox.forms import (
    NestedGroupModelBulkEditForm, PrimaryModelBulkEditForm,
)
from tenancy.models import *
from utilities.forms.fields import DynamicModelChoiceField
from utilities.forms.rendering import FieldSet
from ..models import SecretRole

__all__ = [
    'SecretBulkEditForm',
    'SecretRoleBulkEditForm',
]


class SecretRoleBulkEditForm(NestedGroupModelBulkEditForm):
    parent = DynamicModelChoiceField(
        label=_('Parent'),
        queryset=SecretRole.objects.all(),
        required=False
    )

    model = SecretRole
    nullable_fields = ('parent', 'description', 'comments')


class SecretBulkEditForm(PrimaryModelBulkEditForm):
    role = DynamicModelChoiceField(
        label=_('Group'),
        queryset=SecretRole.objects.all(),
        required=False
    )

    model = Tenant
    fieldsets = (
        FieldSet('role', 'description'),
    )
    nullable_fields = ('description')
