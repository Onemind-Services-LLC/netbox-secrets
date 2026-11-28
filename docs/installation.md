# Setup (Installation & Configuration)

## Requirements

- A supported NetBox installation
- Python environment with access to NetBox dependencies
- Database already configured for NetBox

## Install from PyPI

```shell
pip install netbox-secrets
```

## Install from Source (development)

```shell
git clone <your-fork-or-repo-url>
cd netbox-secrets
pip install -e .
```

## Enable the Plugin

Add the plugin to NetBox configuration:

```python
# configuration.py
PLUGINS = [
    'netbox_secrets',
]
```

## Configure the Plugin

NetBox Secrets is configured via `PLUGINS_CONFIG` in `configuration.py`.

### Required Settings

#### `apps`

A list of NetBox models where secrets can be assigned and displayed. Each entry is `app_label.model`.

Example:

```python
PLUGINS_CONFIG = {
    'netbox_secrets': {
        'apps': [
            'dcim.device',
            'virtualization.virtualmachine',
        ],
    }
}
```

### Optional Settings

#### `display_default`

Controls where the secrets panel appears on supported object pages.

- Type: `str`
- Default: `tab_view`
- Allowed values: `left_page`, `right_page`, `full_width_page`, `tab_view`

#### `display_setting`

Overrides `display_default` per model.

- Type: `dict`
- Example:

```python
PLUGINS_CONFIG = {
    'netbox_secrets': {
        'apps': ['dcim.device', 'virtualization.virtualmachine'],
        'display_default': 'tab_view',
        'display_setting': {
            'dcim.device': 'full_width_page',
            'virtualization.virtualmachine': 'right_page',
        },
    }
}
```

#### `public_key_size`

Minimum RSA key size allowed for user keys. This is also the default size used when generating a new key pair from the UI or API without an explicit `key_size`.

- Type: `int`
- Default: `2048`

#### `top_level_menu`

Whether the plugin appears as a top-level menu item.

- Type: `bool`
- Default: `False`

### Related NetBox Settings

These are standard NetBox settings that affect session key cookies:

- `SESSION_COOKIE_SECURE`
- `LOGIN_TIMEOUT`

Refer to the NetBox security configuration docs for details.

## Run Migrations and Collect Static Files

```shell
./manage.py migrate
./manage.py collectstatic --no-input
```

## Upgrade

1) Upgrade the package

```shell
pip install --upgrade netbox-secrets
```

2) Run migrations and collectstatic again

```shell
./manage.py migrate
./manage.py collectstatic --no-input
```

## Uninstall

> **Warning:** Uninstalling permanently deletes every secret, secret role and user key. Secrets are encrypted, so they
> cannot be recovered afterwards. Export anything you need and take a database backup first.

The plugin cleans up after itself, but only while it is still installed. Run the cleanup command **before** removing
the plugin from `PLUGINS` and uninstalling the package.

1) Preview what will be removed:

```shell
./manage.py netbox_secrets_uninstall --dry-run
```

2) Run the cleanup. You will be asked to type `uninstall` to confirm (use `--no-input` to skip the prompt):

```shell
./manage.py netbox_secrets_uninstall
```

This deletes, in a single transaction:

- the plugin's change log entries (NetBox does not allow content types to be deleted while these exist)
- the plugin's content types, together with their permissions, journal entries and search entries
- the plugin's database tables, triggers and functions, and its rows in `django_migrations`

The PostgreSQL `ltree` extension is shared with NetBox and is left in place.

Custom fields, custom links, event rules, export templates, saved filters, tags and object permissions that you attached
to the plugin's models are unlinked from them. Those that applied *only* to the plugin's models are kept and listed in
the output; pass `--delete-orphans` to delete them as well. Objects that are also linked to other models are never
deleted.

3) Remove the plugin from `PLUGINS` (and its entry from `PLUGINS_CONFIG`) in `configuration.py`
4) Uninstall the package, and remove it from `local_requirements.txt` if it is listed there: `pip uninstall netbox-secrets`
5) Restart NetBox

If the plugin is already uninstalled, follow NetBox's [Removing a Plugin](https://netboxlabs.com/docs/netbox/en/stable/plugins/removal/)
guide instead. Before deleting the content types, delete the change log entries that reference them, and drop the
`netbox_secrets_secretrole_ltree_*` SQL functions along with the tables.
