# NetBox Secrets (NetBox v4.5)

## Overview
NetBox Secrets is a NetBox plugin for securely storing and managing secrets (passwords, API keys, tokens,
certificates, etc.) with end-to-end encryption. Secrets are encrypted at rest and can be assigned to any
supported NetBox object.

This document consolidates all plugin documentation for NetBox v4.5.x and summarizes the changes in this release.

## Compatibility
- **NetBox**: 4.5.x
- **Plugin**: 3.0.x (current branch)

## Features
- RSA-based master key distribution per user
- AES-256 encryption for secret values with validation hashing
- Session-key workflow for encryption/decryption in API and UI
- Hierarchical secret roles (MPTT)
- REST API + GraphQL integration
- Assign secrets to configured NetBox object types
- UI workflow for user keys, session keys, and secret management
- Legacy API compatibility until NetBox v4.6

## What’s New in the 4.5-Compatible Release
- NetBox v4.5 compatibility updates across models, views, API, GraphQL
- Session-key API consolidated to `/session-key/`
- SecretRole hierarchy (MPTT)
- Inline JS for UI workflows (no build step or static bundle)
- Documentation reorganized under `docs/`
- Tests reorganized by component type for full coverage

## Changes Summary (This Release)
### Features
- Hierarchical SecretRoles with parent/child relationships (MPTT)
- Session-key workflow for API and UI with cookie + header support

### Enhancements
- Stronger RSA key validation in forms and model validation
- Improved secret encryption flow with padding + hash validation
- More explicit API responses and error messages
- Inline JS for session-key UX (removes build toolchain)

### Bug Fixes
- Prevent deletion of last active UserKey when secrets exist
- Safer master key handling and activation workflows
- Cleaner serializer handling for encrypted plaintext

### Breaking Changes
- NetBox < 4.5 is no longer supported
- `POST /get-session-key/` removed (use `/session-key/`)
- `/session-keys/` deprecated in favor of `/session-key/` (removal planned in v4.6)
- SecretRole is now hierarchical (MPTT migration required)
- Static JS bundle removed; UI uses inline JS

## Architecture
### Models
- **UserKey**: RSA public key storage and encrypted master key copy
- **SessionKey**: per-user session key (XOR encrypted master key + hash)
- **SecretRole**: hierarchical categories for secrets (MPTT)
- **Secret**: AES-256 encrypted secret with validation hash

### API
DRF viewsets for secrets, roles, user keys, session keys, plus RSA key generation.

### GraphQL
Strawberry types and filters for `Secret` and `SecretRole` with sensitive fields excluded.

### UI
NetBox generic views, tables, and forms. Inline JS handles session-key UX and API calls.

### Template Extensions
Secrets panel or tab added to configured object types from `PLUGINS_CONFIG['netbox_secrets']['apps']`.

### Signals
`GenericRelation` added to configured object types on DB connection to enable `.secrets` access.

## Installation & Configuration
Installation and configuration steps are consolidated in [docs/installation.md](installation.md). Please follow that guide to avoid drift.

## Models Overview
### UserKey
- One-to-one with `User`
- Stores RSA public key and encrypted master key copy
- Prevents deletion of the last active key while secrets exist

### SessionKey
- One-to-one with `UserKey`
- XOR-encrypted master key + hash of session key
- Used to encrypt/decrypt secrets during a session

### SecretRole
- Hierarchical (MPTT)
- Supports parent/child relationships and nested filtering

### Secret
- AES-256-CFB encrypted payload + random padding
- Validation hash ensures integrity
- Generic relation to configured object types

## API Reference
Base path:
```
/api/plugins/secrets/
```

### Session Keys (current)
- `GET /session-key/`
- `POST /session-key/`
- `DELETE /session-key/`

Session keys must be provided to create or update secrets:
- `X-Session-Key` header (base64)
- `netbox_secrets_sessionid` cookie

### User Keys
- `GET /user-keys/`
- `POST /user-keys/`
- `GET /user-keys/{id}/`
- `PATCH /user-keys/{id}/`
- `DELETE /user-keys/{id}/`
- `POST /user-keys/activate/`

### Secret Roles
- `GET /secret-roles/`
- `POST /secret-roles/`
- `GET /secret-roles/{id}/`
- `PATCH /secret-roles/{id}/`
- `DELETE /secret-roles/{id}/`

### Secrets
- `GET /secrets/`
- `POST /secrets/`
- `GET /secrets/{id}/`
- `PATCH /secrets/{id}/`
- `DELETE /secrets/{id}/`

### RSA Key Pair Generation
- `GET /generate-rsa-key-pair/` (optional `key_size`)

### Deprecated Endpoints (supported until NetBox v4.6)
- `GET|POST /session-keys/` → use `/session-key/`
- `GET|DELETE /session-keys/{id}/` → use `/session-key/` (ID ignored)
- `POST /activate-user-key/` → use `/user-keys/activate/`

### Removed Endpoint
- `POST /get-session-key/` → use `/session-key/`

## Permissions
- `netbox_secrets.view_*` for read operations
- `netbox_secrets.add_*`, `change_*`, `delete_*` for CRUD
- `netbox_secrets.change_userkey` required for activating user keys

## NetBox v4.5 Compatibility Notes
- SecretRole moved to `NestedGroupModel` with MPTT fields
- Owner fields added to Secret and SecretRole
- GraphQL types updated to Strawberry patterns
- UI and filters updated for NetBox 4.5 patterns

## Breaking Changes
- NetBox < 4.5 no longer supported
- `POST /get-session-key/` removed
- `session-keys` endpoints deprecated (remove in v4.6)
- SecretRole hierarchy migration required
- Static JS bundle removed (inline JS now used)

## Upgrade Guide (from previous versions)
1) Back up your database
2) Upgrade plugin version
3) Apply migrations:
   ```shell
   ./manage.py migrate
   ```
4) Update API clients to `/session-key/`
5) Verify SecretRole hierarchy and secret access

## Migration Notes
The `0009_*` migration adds MPTT fields and owner fields. Verify that:
- SecretRole parent/child relationships are correct
- Secrets remain accessible and decryptable
- User keys are still valid

## Examples
Create a session key:
```bash
curl -X POST \
  -H "Authorization: Token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"private_key":"-----BEGIN RSA PRIVATE KEY-----..."}' \
  https://netbox.example.com/api/plugins/secrets/session-key/
```

Create a secret:
```bash
curl -X POST \
  -H "Authorization: Token <TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-Session-Key: <BASE64_SESSION_KEY>" \
  -d '{"assigned_object_type":"dcim.device","assigned_object_id":123,"role":1,"name":"admin","plaintext":"SuperSecret"}' \
  https://netbox.example.com/api/plugins/secrets/secrets/
```

## Troubleshooting
- **No UserKey found**: create a UserKey and activate it
- **UserKey inactive**: activate via `/user-keys/activate/`
- **Invalid private key**: confirm PEM format and correct key
- **Secrets not visible**: ensure target model is listed in `PLUGINS_CONFIG['apps']`
- **Cannot delete last active UserKey**: create and activate another key first

## Development Setup
```shell
pip install -e .
pre-commit run -a
```

No JS build step required (inline JS is served from templates).

## Testing
```shell
python manage.py test netbox_secrets
```

### Coverage
```shell
coverage run --source=netbox_secrets manage.py test netbox_secrets
coverage report
```

Templates and migrations are excluded via `.coveragerc`.
