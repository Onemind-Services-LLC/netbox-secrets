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

Installation steps are consolidated in [docs/installation.md](docs/installation.md). Follow that guide, then create your first User Key.

## Documentation

Full documentation lives in [docs/index.md](docs/index.md). A consolidated NetBox v4.5 document is available at
[docs/README.md](docs/README.md).

## Release Notes (NetBox v4.5)

Highlights for the 4.5-compatible release:
- NetBox v4.5 compatibility across models, views, API, GraphQL
- Session-key API consolidated to `/session-key/`
- SecretRole hierarchy (MPTT) with migration `0009_*`
- Inline JS (no build pipeline)

Breaking changes and full details:
- NetBox < 4.5 no longer supported
- `POST /get-session-key/` removed (use `/session-key/`)
- `/session-keys/` deprecated until NetBox v4.6
- SecretRole hierarchy migration required

See [docs/README.md](docs/README.md) for the complete change list, upgrade steps, and API details.

## Deprecations & Migration

- Legacy API endpoints are supported until NetBox v4.6. See [docs/api.md](docs/api.md) for the deprecated routes and
  their replacements.
- For upgrade notes (including SecretRole hierarchy changes), see [docs/migration.md](docs/migration.md).

## Support

- Issues and feature requests: open a ticket in your internal tracker or this repository's issue tracker.
- Security concerns: see `SECURITY.md`.

## License

See `LICENSE.md`.
