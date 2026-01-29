# Migration from netbox-secretstore

This plugin includes database migrations to copy data from the legacy `netbox-secretstore` plugin, if its tables are
present. Migration is one-way.

## Recommended Steps

1) Back up your database.
2) Install and enable both plugins in `PLUGINS`.
3) Run migrations:

```shell
./manage.py migrate
```

4) Verify secrets, roles, and user keys in NetBox Secrets.
5) Remove `netbox-secretstore` from `PLUGINS` and uninstall it once you are satisfied.

## Notes

- The master key cannot be recovered if you remove the last active User Key.
- Always validate decrypted secrets after migration before removing the old plugin.
