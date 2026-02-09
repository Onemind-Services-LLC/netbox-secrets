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
- Setup (installation + configuration): [docs/installation.md](docs/installation.md)
- Then create your first User Key in the UI

## Documentation
- Setup: [docs/installation.md](docs/installation.md)
- Usage: [docs/usage.md](docs/usage.md)
- API: [docs/api.md](docs/api.md)
- Cryptography: [docs/cryptography.md](docs/cryptography.md)
- Permissions: [docs/permissions.md](docs/permissions.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md)

## Release Notes
- Release notes are maintained in GitHub for each version.

## Deprecations & Migration
- Legacy API endpoints supported until NetBox v4.6: [docs/api.md](docs/api.md)

## Legacy Migration
Legacy guidance for netbox-secretstore migrations is available here:
[docs/legacy-migration.md](docs/legacy-migration.md)

## Support
- Issues and feature requests: open a ticket in your internal tracker or this repository's issue tracker.
- Security concerns: see `SECURITY.md`.

## License

See `LICENSE.md`.
