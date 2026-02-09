import django_tables2 as tables
from django.utils.translation import gettext as _

from netbox.tables import NestedGroupModelTable, NetBoxTable, PrimaryModelTable, columns
from tenancy.tables.columns import ContactsColumnMixin
from .models import Secret, SecretRole, UserKey

__all__ = (
    'SecretTable',
    'SecretRoleTable',
    'UserKeyTable',
)


class UserKeyTable(NetBoxTable):
    user = tables.Column(linkify=True)
    is_active = columns.BooleanColumn(
        verbose_name=_('Is Active'),
    )
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:userkey_list')
    actions = columns.ActionsColumn(actions=('delete',))

    class Meta(NetBoxTable.Meta):
        model = UserKey
        fields = ('pk', 'id', 'user', 'is_active', 'created', 'last_updated', 'tags', 'actions')
        default_columns = ('id', 'user', 'is_active', 'actions')


class SecretRoleTable(NestedGroupModelTable):
    secret_count = columns.LinkedCountColumn(
        viewname='plugins:netbox_secrets:secret_list',
        url_params={'role_id': 'pk'},
        verbose_name=_('Secrets'),
    )
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:secretrole_list')

    class Meta(NestedGroupModelTable.Meta):
        model = SecretRole
        fields = (
            'pk',
            'id',
            'name',
            'parent',
            'secret_count',
            'description',
            'comments',
            'slug',
            'tags',
            'created',
            'last_updated',
            'actions',
        )
        default_columns = ('pk', 'name', 'secret_count', 'description')


class SecretTable(PrimaryModelTable, ContactsColumnMixin):
    name = tables.Column(linkify=True)
    role = tables.Column(linkify=True)
    assigned_object_type = columns.ContentTypeColumn(verbose_name=_('Object Type'))
    assigned_object = tables.Column(linkify=True, orderable=False, verbose_name=_('Object'))
    tags = columns.TagColumn(url_name='plugins:netbox_secrets:secret_list')

    class Meta(NetBoxTable.Meta):
        model = Secret
        fields = (
            'pk',
            'id',
            'name',
            'role',
            'assigned_object_type',
            'assigned_object',
            'description',
            'comments',
            'contacts',
            'tags',
            'created',
            'last_updated',
            'actions',
        )
        default_columns = ('pk', 'name', 'role', 'assigned_object_type', 'assigned_object', 'description')
