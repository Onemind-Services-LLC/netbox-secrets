# Legacy Migration: netbox-secretstore → netbox-secrets

This guide is **legacy** and applies only to older environments still using `netbox-secretstore`.
If you are on NetBox 4.5+ and already using `netbox-secrets`, you do not need this.

## Important
- Migration is **one-way**. You cannot migrate back to `netbox-secretstore`.
- Ensure the database does **not** already contain `netbox-secrets` tables/data.

## Assumptions
- **NetBox v3.4.x**
- **netbox-secretstore v1.7.x**

## Steps
1) Install the migration build of netbox-secretstore:
   ```shell
   pip install git+https://github.com/Onemind-Services-LLC/netbox-secretstore@migration/nb34
   ```
   You should now have netbox-secretstore **v1.4.4** installed.

2) Add **both** plugins to `configuration.py` before migrating.

3) Run migrations:
   ```shell
   python manage.py migrate
   ```

4) Readjust indices for `netbox-secrets`:
   ```shell
   python manage.py sqlsequencereset netbox_secrets
   ```
   Run the output of the above command directly in your database.

5) Remove `netbox-secretstore` from `PLUGINS` and uninstall it when satisfied.

You may need to manually clean up legacy tables after migration.
