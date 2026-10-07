from django.contrib.postgres.indexes import GistIndex
from django.contrib.postgres.operations import CreateExtension
from django.db import migrations, models

import netbox.models.ltree
from utilities.ltree import InstallLtreeTriggers
from utilities.mptt_to_ltree import assert_paths_populated_sql, populate_paths_sql


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0011_remove_redundant_indexes'),
    ]

    operations = [
        # Enable the ltree extension first so the migration fails fast if it is missing.
        CreateExtension('ltree'),

        # Switch parent from mptt.fields.TreeForeignKey to django.db.models.ForeignKey.
        migrations.AlterField(
            model_name='secretrole',
            name='parent',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.CASCADE,
                related_name='children',
                to='netbox_secrets.secretrole',
            ),
        ),

        # Add path (nullable initially).
        migrations.AddField(
            model_name='secretrole',
            name='path',
            field=netbox.models.ltree.LtreeField(
                blank=True,
                editable=False,
                null=True,
            ),
        ),

        # Add sort_path with natural_sort collation to match name.
        migrations.AddField(
            model_name='secretrole',
            name='sort_path',
            field=models.TextField(
                blank=True,
                default='',
                editable=False,
                db_collation='natural_sort',
            ),
        ),

        # Install triggers maintaining both path and sort_path.
        InstallLtreeTriggers(
            'netbox_secrets_secretrole',
            name_column='name',
        ),

        # Populate path and sort_path for existing rows.
        migrations.RunSQL(
            sql=populate_paths_sql(
                'netbox_secrets_secretrole',
                sort_path=True,
            ),
            reverse_sql=migrations.RunSQL.noop,
        ),

        # Fail if any row has a NULL path.
        migrations.RunSQL(
            sql=assert_paths_populated_sql(
                'netbox_secrets_secretrole',
            ),
            reverse_sql=migrations.RunSQL.noop,
        ),

        # Make path non-null after successful population.
        migrations.AlterField(
            model_name='secretrole',
            name='path',
            field=netbox.models.ltree.LtreeField(
                blank=True,
                default='',
                editable=False,
            ),
        ),

        # Use hierarchical ordering.
        migrations.AlterModelOptions(
            name='secretrole',
            options={'ordering': ('sort_path',)},
        ),

        # Drop legacy MPTT columns.
        migrations.RemoveField(
            model_name='secretrole',
            name='lft',
        ),

        migrations.RemoveField(
            model_name='secretrole',
            name='rght',
        ),

        migrations.RemoveField(
            model_name='secretrole',
            name='tree_id',
        ),

        migrations.RemoveField(
            model_name='secretrole',
            name='level',
        ),

        # GiST index for ltree path queries.
        migrations.AddIndex(
            model_name='secretrole',
            index=GistIndex(
                fields=['path'],
                name='secrets_secretrole_path_gist',
            ),
        ),

        # B-tree index for sort_path ordering.
        migrations.AddIndex(
            model_name='secretrole',
            index=models.Index(
                fields=['sort_path'],
                name='secrets_sr_sort_path_idx',
            ),
        ),
    ]

