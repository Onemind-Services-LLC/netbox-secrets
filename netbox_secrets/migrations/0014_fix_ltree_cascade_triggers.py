"""Reinstall SecretRole's ltree triggers with a restore-safe WHEN clause.

NetBox 4.7.0 installed an AFTER cascade trigger whose `WHEN` clause compared
ltree path values with `IS DISTINCT FROM`. During a `pg_dump` restore,
`search_path` is set to the empty string, so PostgreSQL cannot resolve the
ltree equality operator needed to create that trigger. The `CREATE TRIGGER`
statement fails; when the dump is replayed with `psql`'s default error handling,
the restore can still finish with the AFTER cascade trigger missing. The BEFORE
compute-path trigger does not use this `WHEN` expression and is not affected.
See NetBox issue #23130.

NetBox 4.7.1 corrected the trigger condition by comparing `path::text`, which
uses the built-in text equality operator and works with an empty `search_path`.
`ReinstallLtreeTriggers` installs that corrected definition. This covers both
an affected database restored from a v4.7.0 dump, where the cascade trigger may
be missing, and a database upgraded in place, where the old cascade trigger
remains installed and would be omitted again when a later dump is restored.

This migration repairs trigger definitions only. It does not detect or repair
`path` or `sort_path` values that became stale while the cascade trigger was
missing. Check the plugin's SecretRole table separately and rebuild stale
values where necessary; do not assume NetBox's core repair process covers
plugin-owned tables.

Reversing this migration is intentionally a no-op: it only replaces the
triggers originally installed by `0012_ltree_paths`. Reversing this migration
alone must leave those triggers in place. If rolling back past `0012`, that
migration's reverse operation removes the triggers along with the original
ltree installation. Re-applying `0012` installs triggers using the definition
provided by the NetBox version then in use.
"""
from django.db import migrations

from utilities.ltree import ReinstallLtreeTriggers


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0013_alter_secretrole_options_alter_secret_owner_and_more'),
    ]

    operations = [
        ReinstallLtreeTriggers(
            'netbox_secrets_secretrole',
            name_column='name',
        ),
    ]
