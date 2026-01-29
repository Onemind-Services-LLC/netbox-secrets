# API Reference

Base path for all endpoints:

```
/api/plugins/secrets/
```

Authentication uses standard NetBox API auth (token or session). Most endpoints require authentication; user key
activation additionally requires permission.

## Session Key

### GET /session-key/

Returns the current user's session key metadata.

- 200: Session key exists
- 404: No session key

### POST /session-key/

Creates or returns a session key for the current user.

Request body:

```json
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "preserve_key": true
}
```

- `private_key` is required
- `preserve_key` defaults to `false`

Response includes `session_key` (base64). If using session auth, the key is also stored as a cookie.

### DELETE /session-key/

Deletes the current user's session key and clears the cookie.

## RSA Key Pair Generation

### GET /generate-rsa-key-pair/

Generates a new RSA key pair.

Query params:

- `key_size` (optional): integer between 2048 and 8192 in steps of 256

Response:

```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "key_size": 2048
}
```

## User Keys

### GET /user-keys/

List user keys. Supports standard NetBox filters and search. Examples:

- `?user_id=1`
- `?user=username`

### POST /user-keys/

Create a user key. If you have permission, you may set `user` to create a key for another user; otherwise the
requesting user is used.

```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "user": 123
}
```

### GET /user-keys/{id}/

Retrieve a user key.

### PATCH /user-keys/{id}/

Update a user key (public key, tags, custom fields). The `user` field is immutable.

### DELETE /user-keys/{id}/

Delete a user key. Deletion is blocked if this is the last active key and secrets exist.

### POST /user-keys/activate/

Bulk activate user keys with an administrator's private key.

```json
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "user_key_ids": [1, 2, 3]
}
```

Requires `netbox_secrets.change_userkey` permission and an active User Key.

## Secret Roles

Standard CRUD endpoints:

- `GET /secret-roles/`
- `POST /secret-roles/`
- `GET /secret-roles/{id}/`
- `PATCH /secret-roles/{id}/`
- `DELETE /secret-roles/{id}/`

## Secrets

Standard CRUD endpoints:

- `GET /secrets/`
- `POST /secrets/`
- `GET /secrets/{id}/`
- `PATCH /secrets/{id}/`
- `DELETE /secrets/{id}/`

### Session Key Requirement

A session key is required to create or update secrets. Provide it in one of these ways:

- `X-Session-Key` header (base64)
- `netbox_secrets_sessionid` cookie

If no session key is provided, create/update requests will fail. For read operations, `plaintext` is only populated when
the session key is provided.

### Create Secret Example

```json
{
  "assigned_object_type": "dcim.device",
  "assigned_object_id": 123,
  "role": 1,
  "name": "admin",
  "plaintext": "SuperSecretPassword"
}
```

## GraphQL

The plugin exposes GraphQL types for `Secret` and `SecretRole`. The `Secret` type excludes `plaintext`, `hash`, and
`ciphertext` fields to avoid leaking sensitive data.
