from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _

from netbox.forms import NetBoxModelFilterSetForm
from tenancy.models import Tenant
from utilities.forms.fields import (
    ContentTypeMultipleChoiceField,
    DynamicModelMultipleChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet
from ..constants import *
from ..models import Secret, SecretRole, TenantMembership, TenantServiceAccount, TenantSecret

__all__ = [
    'SecretRoleFilterForm',
    'SecretFilterForm',
    'TenantMembershipFilterForm',
    'TenantServiceAccountFilterForm',
    'TenantSecretFilterForm',
]


class SecretRoleFilterForm(NetBoxModelFilterSetForm):
    model = SecretRole
    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('id', name=_('Secret Role')),
    )
    id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Roles Name'))
    tag = TagFilterField(model)


class SecretFilterForm(NetBoxModelFilterSetForm):
    model = Secret

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('id', name=_('Secret')),
        FieldSet('role_id', 'assigned_object_type_id', name=_("Attributes")),
    )

    id = DynamicModelMultipleChoiceField(queryset=Secret.objects.all(), required=False, label=_('Name'))
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label='Object type(s)',
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))
    tag = TagFilterField(model)


#
# Tenant Crypto Filter Forms
#


class TenantMembershipFilterForm(NetBoxModelFilterSetForm):
    model = TenantMembership

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('tenant_id', 'user_id', 'role', name=_('Membership')),
    )

    tenant_id = DynamicModelMultipleChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_('Tenant'),
    )
    user_id = DynamicModelMultipleChoiceField(
        queryset=get_user_model().objects.all(),
        required=False,
        label=_('User'),
    )
    tag = TagFilterField(model)


class TenantServiceAccountFilterForm(NetBoxModelFilterSetForm):
    model = TenantServiceAccount

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('tenant_id', 'enabled', name=_('Service Account')),
    )

    tenant_id = DynamicModelMultipleChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_('Tenant'),
    )
    tag = TagFilterField(model)


class TenantSecretFilterForm(NetBoxModelFilterSetForm):
    model = TenantSecret

    fieldsets = (
        FieldSet('q', 'filter_id', 'tag', name=None),
        FieldSet('tenant_id', 'created_by', name=_('Secret')),
    )

    tenant_id = DynamicModelMultipleChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_('Tenant'),
    )
    created_by = DynamicModelMultipleChoiceField(
        queryset=get_user_model().objects.all(),
        required=False,
        label=_('Created By'),
    )
    tag = TagFilterField(model)
