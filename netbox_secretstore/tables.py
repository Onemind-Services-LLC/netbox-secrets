import django_tables2 as tables

from utilities.tables import BaseTable, LinkedCountColumn, TagColumn, ToggleColumn
from netbox_secretstore.utils.tables import PluginButtonsColumn
from .models import SecretRole, Secret


#
# Secret roles
#

class SecretRoleTable(BaseTable):
    pk = ToggleColumn()
    name = tables.Column(
        linkify=True
    )
    secret_count = LinkedCountColumn(
        viewname='plugins:netbox_secretstore:secret_list',
        url_params={'role_id': 'pk'},
        verbose_name='Secrets'
    )
    actions = PluginButtonsColumn(SecretRole)

    class Meta(BaseTable.Meta):
        model = SecretRole
        fields = ('pk', 'name', 'secret_count', 'description', 'slug', 'actions')
        default_columns = ('pk', 'name', 'secret_count', 'description', 'actions')


#
# Secrets
#

class SecretTable(BaseTable):
    pk = ToggleColumn()
    id = tables.Column(  # Provides a link to the secret
        linkify=True
    )
    assigned_object = tables.Column(
        linkify=True,
        verbose_name='Assigned object'
    )
    role = tables.Column(
        linkify=True
    )
    tags = TagColumn(
        url_name='plugins:netbox_secretstore:secret_list'
    )

    class Meta(BaseTable.Meta):
        model = Secret
        fields = ('pk', 'id', 'assigned_object', 'role', 'name', 'last_updated', 'hash', 'tags')
        default_columns = ('pk', 'id', 'assigned_object', 'role', 'name', 'last_updated')
