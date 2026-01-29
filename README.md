# NetBox Secrets

NetBox Secrets is a NetBox plugin for securely storing and managing secrets (passwords, API keys, tokens, certificates, etc.)
with end-to-end encryption. Secrets are encrypted at rest and can be assigned to any supported NetBox object.

## Highlights

- Public-key (RSA) based master key distribution
- AES-256 encryption for secret values
- Session-key workflow for encryption/decryption
- Flexible secret assignment to NetBox objects
- Secret roles for organization and access control
- REST API + GraphQL integration

## Compatibility

| NetBox Version | Plugin Version |
|----------------|----------------|
| 3.3.x          | 1.4.x - 1.5.x  |
| 3.4.x          | 1.6.x - 1.7.x  |
| 3.5.x          | 1.8.x          |
| 3.6.x          | 1.9.x          |
| 3.7.x          | 1.10.x         |
| 4.0.x          | 2.0.x          |
| 4.1.x          | 2.1.x          |
| 4.2.x          | 2.2.x          |
| 4.3.x          | 2.3.x          |
| 4.4.x          | 2.4.x          |
| 4.5.x          | 3.0.x          |

## Quickstart

1) Install the plugin

```shell
pip install netbox-secrets
```

2) Enable it in your NetBox configuration:

```python
# configuration.py
PLUGINS = [
    'netbox_secrets',
]

PLUGINS_CONFIG = {
    'netbox_secrets': {
        'apps': [
            'dcim.device',
            'virtualization.virtualmachine',
        ],
        'display_default': 'tab_view',
        'public_key_size': 2048,
        'top_level_menu': False,
    }
}
```

3) Run migrations and collect static assets:

```shell
./manage.py migrate
./manage.py collectstatic --no-input
```

4) Begin by creating your first User Key.

## Documentation

Full documentation lives in [docs/index.md](docs/index.md).

## Support

- Issues and feature requests: open a ticket in your internal tracker or this repository's issue tracker.
- Security concerns: see `SECURITY.md`.

## License

See `LICENSE.md`.
