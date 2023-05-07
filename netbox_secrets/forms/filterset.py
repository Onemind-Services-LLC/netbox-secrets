from django import forms
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _
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
    q = forms.CharField(required=False, label=_('Search'))
    name = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False)


class SecretFilterForm(NetBoxModelFilterSetForm):
    model = Secret

    fieldsets = (
        (None, ('q', 'filter_id', 'tag')),
        ('Attributes', ('role_id', 'assigned_object_type_id')),
    )

    q = forms.CharField(required=False, label=_('Search'))
    assigned_object_type_id = ContentTypeMultipleChoiceField(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        required=False,
        label='Object type(s)',
    )
    role_id = DynamicModelMultipleChoiceField(queryset=SecretRole.objects.all(), required=False, label=_('Role'))
    tag = TagFilterField(model)
