import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from .models import Secret, SecretRole

#
# Secret roles
#


class SecretRoleTable(NetBoxTable):
    name = tables.Column(linkify=True)
    secret_count = columns.LinkedCountColumn(
        viewname='plugins:netbox_secrets:secret_list',
        url_params={'role_id': 'pk'},
        verbose_name='Secrets',
    )

    class Meta(NetBoxTable.Meta):
        model = SecretRole
        fields = ('pk', 'id', 'name', 'secret_count', 'description', 'slug', 'actions')
        default_columns = ('id', 'name', 'secret_count', 'description', 'actions')


#
# Secrets
#


class SecretTable(NetBoxTable):
    name = tables.Column(linkify=True)
    assigned_object_type = columns.ContentTypeColumn(verbose_name='Object type')
    assigned_object = tables.Column(linkify=True, orderable=False, verbose_name='Object')
    role = tables.Column(linkify=True)
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:secret_list')

    class Meta(NetBoxTable.Meta):
        model = Secret
        fields = (
            'pk',
            'id',
            'name',
            'assigned_object_type',
            'assigned_object',
            'role',
            'created',
            'last_updated',
            'tags',
        )
        default_columns = ('pk', 'id', 'name', 'assigned_object_type', 'assigned_object', 'role', 'actions')
