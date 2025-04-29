import django_tables2 as tables
from django.utils.translation import gettext as _

from netbox.tables import NetBoxTable, columns
from .models import Secret, SecretRole, UserKey


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
    comments = columns.MarkdownColumn()
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:secretrole_list')

    class Meta(NetBoxTable.Meta):
        model = SecretRole
        fields = (
            'pk',
            'id',
            'name',
            'secret_count',
            'description',
            'slug',
            'comments',
            'tags',
            'created',
            'last_updated',
            'actions',
        )
        default_columns = ('id', 'name', 'secret_count', 'description', 'actions')


#
# Secrets
#


class SecretTable(NetBoxTable):
    name = tables.Column(linkify=True)
    assigned_object_type = columns.ContentTypeColumn(verbose_name='Object type')
    assigned_object = tables.Column(linkify=True, orderable=False, verbose_name='Object')
    role = tables.Column(linkify=True)
    comments = columns.MarkdownColumn()
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:secret_list')

    class Meta(NetBoxTable.Meta):
        model = Secret
        fields = (
            'pk',
            'id',
            'name',
            'description',
            'assigned_object_type',
            'assigned_object',
            'role',
            'comments',
            'created',
            'last_updated',
            'tags',
        )
        default_columns = (
            'pk',
            'id',
            'name',
            'description',
            'assigned_object_type',
            'assigned_object',
            'role',
            'actions',
        )


class UserKeyTable(NetBoxTable):
    user = tables.Column(linkify=True)
    is_active = columns.BooleanColumn(
        verbose_name=_('Is Active'),
        orderable=False,
    )
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:userkey_list')
    actions = columns.ActionsColumn(actions=('delete',))

    class Meta(NetBoxTable.Meta):
        model = UserKey
        fields = (
            'pk',
            'user',
            'is_active',
            'created',
            'last_updated',
            'tags',
            'actions',
        )
        default_columns = (
            'pk',
            'id',
            'user',
            'is_active',
        )
