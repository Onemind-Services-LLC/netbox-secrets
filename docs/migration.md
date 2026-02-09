# Migration from netbox-secretstore

This plugin includes database migrations to copy data from the legacy `netbox-secretstore` plugin, if its tables are
present. Migration is one-way.

## NetBox Secrets Upgrade Notes (NetBox 4.5)

If you are upgrading the plugin on NetBox 4.5.x:

- SecretRole is now hierarchical (MPTT). Migration `0009_*` adds tree fields; after migrating, verify roles and
  relationships, and run tests in your NetBox environment to confirm older data migrated cleanly.
- Several API endpoints are deprecated but still supported until NetBox v4.6. See `docs/api.md` for mappings and
  update client integrations early.

## Recommended Steps

1) Back up your database.
2) Ensure both plugins are installed and enabled (see `docs/installation.md`).
3) Run migrations:

```shell
./manage.py migrate
```

4) Verify secrets, roles, and user keys in NetBox Secrets.
5) Remove `netbox-secretstore` from `PLUGINS` and uninstall it once you are satisfied.

## Notes

- The master key cannot be recovered if you remove the last active User Key.
- Always validate decrypted secrets after migration before removing the old plugin.
