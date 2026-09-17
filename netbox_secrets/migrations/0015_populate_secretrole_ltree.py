from django.db import migrations

from utilities.ltree import InstallLtreeTriggers
from utilities.mptt_to_ltree import assert_paths_populated_sql, populate_paths_sql


TABLE = 'netbox_secrets_secretrole'


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0014_create_ltree_extension'),
    ]

    operations = [
        # Install triggers which maintain path/sort_path.
        InstallLtreeTriggers(
            TABLE,
            name_column='name',
        ),

        # Populate existing SecretRole hierarchy.
        migrations.RunSQL(
            populate_paths_sql(TABLE, sort_path=True),
            reverse_sql=migrations.RunSQL.noop,
        ),

        # Ensure every existing row received a path.
        migrations.RunSQL(
            assert_paths_populated_sql(TABLE),
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
