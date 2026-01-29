# Configuration

NetBox Secrets is configured via `PLUGINS_CONFIG` in `configuration.py`.

## Required Settings

### `apps`

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

## Optional Settings

### `display_default`

Controls where the secrets panel appears on supported object pages.

- Type: `str`
- Default: `tab_view`
- Allowed values: `left_page`, `right_page`, `full_width_page`, `tab_view`

### `display_setting`

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

### `public_key_size`

Minimum RSA key size allowed for user keys.

- Type: `int`
- Default: `2048`

### `top_level_menu`

Whether the plugin appears as a top-level menu item.

- Type: `bool`
- Default: `False`

## Related NetBox Settings

These are standard NetBox settings that affect session key cookies:

- `SESSION_COOKIE_SECURE`
- `LOGIN_TIMEOUT`

Refer to the NetBox security configuration docs for details.
