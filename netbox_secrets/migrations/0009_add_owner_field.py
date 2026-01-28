# Generated manually for NetBox 4.5 compatibility
# Adds owner field from OwnerMixin (inherited via PrimaryModel)

from importlib import util as importlib_util

from django.db import migrations, models
import django.db.models.deletion


def _has_owner_migration():
    return importlib_util.find_spec('users.migrations.0015_owner') is not None


def _owner_model_exists(state):
    try:
        state.apps.get_model('users', 'Owner')
    except LookupError:
        return False
    return True


def _owner_table_exists(schema_editor):
    return 'users_owner' in schema_editor.connection.introspection.table_names()


def _column_exists(schema_editor, table_name, column_name):
    for column in schema_editor.connection.introspection.get_table_description(
        schema_editor.connection.cursor(),
        table_name,
    ):
        if column.name == column_name:
            return True
    return False


class ConditionalAddField(migrations.AddField):
    def state_forwards(self, app_label, state):
        if _owner_model_exists(state):
            super().state_forwards(app_label, state)

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not _owner_model_exists(to_state):
            return
        if not _owner_table_exists(schema_editor):
            return
        table_name = to_state.apps.get_model(app_label, self.model_name)._meta.db_table
        if _column_exists(schema_editor, table_name, self.name):
            return
        super().database_forwards(app_label, schema_editor, from_state, to_state)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if not _owner_table_exists(schema_editor):
            return
        table_name = from_state.apps.get_model(app_label, self.model_name)._meta.db_table
        if not _column_exists(schema_editor, table_name, self.name):
            return
        super().database_backwards(app_label, schema_editor, from_state, to_state)


class Migration(migrations.Migration):

    if _has_owner_migration():
        dependencies = [
            ('users', '0015_owner'),  # users.Owner model (NetBox 4.5+)
            ('netbox_secrets', '0008_userkey_custom_field_data_userkey_tags'),
        ]
    else:
        dependencies = [
            ('netbox_secrets', '0008_userkey_custom_field_data_userkey_tags'),
        ]

    operations = [
        ConditionalAddField(
            model_name='secret',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.owner',
            ),
        ),
        ConditionalAddField(
            model_name='secretrole',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.owner',
            ),
        ),
    ]
