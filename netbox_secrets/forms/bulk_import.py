from django.utils.translation import gettext_lazy as _

from netbox.forms import (
    NestedGroupModelImportForm,
)
from utilities.forms.fields import CSVModelChoiceField
from ..models import SecretRole

__all__ = [
    'SecretRoleImportForm',
]


class SecretRoleImportForm(NestedGroupModelImportForm):
    parent = CSVModelChoiceField(
        label=_('Parent'),
        queryset=SecretRole.objects.all(),
        required=False,
        to_field_name='name',
        help_text=_('Parent role'),
    )

    class Meta:
        model = SecretRole
        fields = ('name', 'slug', 'parent', 'description', 'owner', 'comments', 'tags')
