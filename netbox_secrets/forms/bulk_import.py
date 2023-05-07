from netbox.forms import NetBoxModelImportForm
from utilities.forms.fields import SlugField

from ..models import SecretRole


class SecretRoleImportForm(NetBoxModelImportForm):
    slug = SlugField()

    class Meta:
        model = SecretRole
        fields = ('name', 'slug')
