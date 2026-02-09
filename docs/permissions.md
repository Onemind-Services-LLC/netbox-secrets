# Permissions

NetBox Secrets uses standard NetBox object permissions. Object-level permissions apply in the REST API as well.

## User Keys

- `netbox_secrets.view_userkey`
- `netbox_secrets.add_userkey`
- `netbox_secrets.change_userkey`
- `netbox_secrets.delete_userkey`

Additional requirement:

- `netbox_secrets.change_userkey` is required to activate other users' keys.

## Secret Roles

- `netbox_secrets.view_secretrole`
- `netbox_secrets.add_secretrole`
- `netbox_secrets.change_secretrole`
- `netbox_secrets.delete_secretrole`

## Secrets

- `netbox_secrets.view_secret`
- `netbox_secrets.add_secret`
- `netbox_secrets.change_secret`
- `netbox_secrets.delete_secret`

## Session Key and RSA Key Pair Endpoints

These endpoints require authentication but do not enforce object permissions.
