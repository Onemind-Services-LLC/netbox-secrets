# API Reference

## Overview

**Base URL:** `/api/plugins/secrets/`

**Authentication:** All endpoints require standard NetBox API authentication (token or session-based). User key activation requires additional `netbox_secrets.change_userkey` permission.

**Workflow:** To work with secrets, follow this sequence:
1. **User Keys** - Create and activate RSA public keys for your user
2. **Session Keys** - Activate your session using your private key
3. **Secret Roles** - Create or select roles to categorize secrets
4. **Secrets** - Create and manage encrypted secrets

**Session Key Requirement:** Creating or updating secrets requires an active session key, provided via:
- `X-Session-Key` header (base64-encoded)
- `netbox_secrets_sessionid` cookie

Without a valid session key, create/update operations will fail. For read operations, the `plaintext` field is only populated when a valid session key is present.

---

## 1. User Key Management

User keys are RSA public keys associated with NetBox users, enabling encrypted secret storage and retrieval. **You must have at least one active user key before you can work with secrets.**

### GET /user-keys/

List all user keys with standard NetBox filtering and search capabilities.

**Query Parameters Examples:**
- `?user_id=1` - Filter by user ID
- `?user=username` - Filter by username
- Standard NetBox filters apply

**Response:**
Returns a paginated list of user key objects.

**Status Codes:**
- `200 OK` - Success

---

### POST /user-keys/

Create a new user key.

**Request Body:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "user": 123
}
```

**Parameters:**
- `public_key` (required) - RSA public key in PEM format
- `user` (optional) - User ID (requires appropriate permissions; defaults to requesting user)

**Permissions:**
- Users can create keys for themselves
- Creating keys for other users requires elevated permissions

**Status Codes:**
- `201 Created` - User key created successfully
- `400 Bad Request` - Invalid public key format
- `403 Forbidden` - Insufficient permissions

---

### GET /user-keys/{id}/

Retrieve details of a specific user key.

**URL Parameters:**
- `id` (required) - User key ID

**Status Codes:**
- `200 OK` - Success
- `404 Not Found` - User key not found

---

### PATCH /user-keys/{id}/

Update an existing user key.

**Updatable Fields:**
- `public_key` - Update the public key
- `tags` - Modify tags
- Custom fields

**Note:** The `user` field is immutable and cannot be changed after creation.

**Status Codes:**
- `200 OK` - User key updated successfully
- `400 Bad Request` - Invalid data
- `404 Not Found` - User key not found

---

### DELETE /user-keys/{id}/

Delete a user key.

**URL Parameters:**
- `id` (required) - User key ID

**Constraints:**
Deletion is blocked if this is the user's last active key and secrets exist that require it.

**Status Codes:**
- `204 No Content` - Successfully deleted
- `400 Bad Request` - Cannot delete (last active key with existing secrets)
- `404 Not Found` - User key not found

---

### POST /user-keys/activate/

Bulk activate one or more user keys using an administrator's private key.

**Request Body:**
```json
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "user_key_ids": [1, 2, 3]
}
```

**Parameters:**
- `private_key` (required) - Administrator's RSA private key
- `user_key_ids` (required) - Array of user key IDs to activate

**Requirements:**
- `netbox_secrets.change_userkey` permission
- Active user key for the requesting administrator

**Status Codes:**
- `200 OK` - User keys activated successfully
- `400 Bad Request` - Missing/invalid private key, empty list, or target user key not found
- `403 Forbidden` - Missing required permission or no active user key

---

## 2. Session Key Management

A session key is required to create or update secrets. It must be obtained by authenticating with your private key.

### GET /session-key/

Retrieves metadata about the current user's session key.

**Status Codes:**
- `200 OK` - Session key exists
- `404 Not Found` - No session key found

---

### POST /session-key/

Creates or returns a session key for the current user.

**Request Body:**
```json
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "preserve_key": true
}
```

**Parameters:**
- `private_key` (required) - User's RSA private key in PEM format
- `preserve_key` (optional) - Whether to preserve the key, defaults to `false`

**Response:**
```json
{
  "session_key": "base64-encoded-session-key"
}
```

Returns the session key (base64-encoded). For session-based authentication, the key is also stored as a cookie.

**Status Codes:**
- `200 OK` - Session key created or retrieved successfully
- `400 Bad Request` - Missing or invalid private key format
- `401 Unauthorized` - User not authenticated

---

### DELETE /session-key/

Deletes the current user's session key and clears the associated cookie.

**Status Codes:**
- `204 No Content` - Session key successfully deleted

---

## 3. Secret Role Management

Secret roles categorize and organize secrets within NetBox. **You must create or have access to at least one secret role before creating secrets.**

### GET /secret-roles/

List all secret roles.

**Query Parameters:**
- Standard NetBox filters, sorting, and pagination apply

**Status Codes:**
- `200 OK` - Success

---

### POST /secret-roles/

Create a new secret role.

**Request Body:**
```json
{
  "name": "Database Credentials",
  "slug": "database-credentials",
  "description": "Credentials for database access"
}
```

**Parameters:**
- `name` (required) - Name of the secret role
- `slug` (required) - URL-friendly identifier
- `description` (optional) - Description of the role

**Status Codes:**
- `201 Created` - Secret role created successfully
- `400 Bad Request` - Invalid data or slug already exists

---

### GET /secret-roles/{id}/

Retrieve a specific secret role.

**URL Parameters:**
- `id` (required) - Secret role ID

**Status Codes:**
- `200 OK` - Success
- `404 Not Found` - Secret role not found

---

### PATCH /secret-roles/{id}/

Update a secret role.

**Updatable Fields:**
- `name` - Update the name
- `slug` - Update the slug
- `description` - Update the description
- `tags` - Modify tags
- Custom fields

**Status Codes:**
- `200 OK` - Secret role updated successfully
- `400 Bad Request` - Invalid data
- `404 Not Found` - Secret role not found

---

### DELETE /secret-roles/{id}/

Delete a secret role.

**URL Parameters:**
- `id` (required) - Secret role ID

**Constraints:**
Deletion may be blocked if secrets are currently assigned to this role.

**Status Codes:**
- `204 No Content` - Successfully deleted
- `400 Bad Request` - Cannot delete (secrets still assigned)
- `404 Not Found` - Secret role not found

---

## 4. Secret Management

Secrets store encrypted sensitive information associated with NetBox objects. **Requires an active session key and a valid secret role.**

### GET /secrets/

List all secrets.

**Query Parameters:**
- `?assigned_object_type=dcim.device` - Filter by object type
- `?assigned_object_id=123` - Filter by object ID
- `?role=1` - Filter by secret role
- `?name=admin` - Filter by name
- Standard NetBox filters, sorting, and pagination apply

**Note:** The `plaintext` field is only populated if a valid session key is provided in the request.

**Status Codes:**
- `200 OK` - Success

---

### POST /secrets/

Create a new secret.

**Request Body:**
```json
{
  "assigned_object_type": "dcim.device",
  "assigned_object_id": 123,
  "role": 1,
  "name": "admin",
  "plaintext": "SuperSecretPassword"
}
```

**Parameters:**
- `assigned_object_type` (required) - Content type of the object (e.g., "dcim.device")
- `assigned_object_id` (required) - ID of the object this secret is associated with
- `role` (required) - Secret role ID
- `name` (required) - Name/identifier for the secret
- `plaintext` (required) - The unencrypted secret value
- `tags` (optional) - Tags for the secret
- Custom fields (optional)

**Requirements:**
- Active session key must be provided via header or cookie
- User must have an active user key

**Note:** The `plaintext` field is encrypted before storage using the user's public key.

**Status Codes:**
- `201 Created` - Secret created successfully
- `400 Bad Request` - Invalid data or missing session key
- `401 Unauthorized` - Not authenticated
- `403 Forbidden` - Insufficient permissions

---

### GET /secrets/{id}/

Retrieve a specific secret.

**URL Parameters:**
- `id` (required) - Secret ID

**Note:** The `plaintext` field is only populated if a valid session key is provided in the request.

**Status Codes:**
- `200 OK` - Success
- `404 Not Found` - Secret not found

---

### PATCH /secrets/{id}/

Update a secret.

**Updatable Fields:**
- `assigned_object_type` - Change the associated object type
- `assigned_object_id` - Change the associated object ID
- `role` - Change the secret role
- `name` - Update the name
- `plaintext` - Update the secret value (requires session key)
- `tags` - Modify tags
- Custom fields

**Requirements:**
- Active session key required if updating `plaintext`

**Status Codes:**
- `200 OK` - Secret updated successfully
- `400 Bad Request` - Invalid data or missing session key (when updating plaintext)
- `404 Not Found` - Secret not found

---

### DELETE /secrets/{id}/

Delete a secret.

**URL Parameters:**
- `id` (required) - Secret ID

**Status Codes:**
- `204 No Content` - Successfully deleted
- `404 Not Found` - Secret not found

---

## Utility Endpoints

### RSA Key Pair Generation

#### GET /generate-rsa-key-pair/

Generates a new RSA key pair for use with NetBox Secrets.

**Query Parameters:**
- `key_size` (optional) - Key size in bits (2048-8192 in steps of 256, default: 2048)

**Response:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
  "key_size": 2048
}
```

**Status Codes:**
- `200 OK` - Key pair generated successfully
- `400 Bad Request` - Invalid key_size value (must be 2048-8192 in 256-bit increments)
- `500 Internal Server Error` - Key generation failed

**Security Note:** Store the private key securely. It should never be shared or transmitted except during session key creation.

---

## GraphQL Support

The plugin provides GraphQL types for querying secrets and secret roles.

**Available Types:**
- `Secret` - Excludes sensitive fields (`plaintext`, `hash`, `ciphertext`) to prevent data leakage
- `SecretRole` - Full access to role metadata

**Security Note:** Sensitive cryptographic fields are intentionally excluded from GraphQL queries to maintain security.

---

## Best Practices

### Key Management
- Generate keys with appropriate size (minimum 2048 bits recommended, 4096 for high security)
- Store private keys securely; they should never be transmitted except during session key creation
- Use the `preserve_key` option judiciously to avoid security risks
- Ensure users have at least one active key before storing secrets
- Plan key rotation carefully to avoid losing access to encrypted secrets

### Session Keys
- Obtain a session key before creating or updating secrets
- Delete session keys when no longer needed to minimize security exposure
- Session keys are user-specific and cannot be shared

### Secret Management
- Always use descriptive names for secrets
- Use secret roles to organize and categorize secrets logically
- Regularly audit and rotate secrets
- Implement proper error handling for all API operations

### API Usage
- Use token-based authentication for API clients
- Implement proper error handling for all error codes
- Respect rate limits and implement exponential backoff for retries
- Always validate response status codes before processing data

---

## Common Error Responses

**Standard HTTP Status Codes:**
- `200 OK` - Successful GET request
- `201 Created` - Successful POST request creating a resource
- `204 No Content` - Successful DELETE request
- `400 Bad Request` - Invalid request parameters or body
- `401 Unauthorized` - Authentication required or failed
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server-side error

**Error Response Format:**
```json
{
  "detail": "Error message describing what went wrong"
}
```

---

## Deprecated Endpoints

The following endpoints are maintained for backward compatibility but will be **removed when the plugin targets NetBox v4.6**. Please migrate to the new endpoints immediately.

### Legacy Endpoint Mappings

| Legacy Endpoint | Replacement | Migration Notes |
|----------------|-------------|-----------------|
| `POST /activate-user-key/` | `POST /user-keys/activate/` | Legacy accepts both `user_keys` and `user_key_ids` parameters. New endpoint only accepts `user_key_ids`. Legacy returns plain success string; new endpoint returns standard JSON. |
| `GET /session-keys/` | `GET /session-key/` | Use singular endpoint for current user's session key. |
| `POST /session-keys/` | `POST /session-key/` | Use singular endpoint for current user's session key. |
| `GET /session-keys/{id}/` | `GET /session-key/` | ID parameter is ignored in legacy endpoint. New endpoint always operates on current user. |
| `DELETE /session-keys/{id}/` | `DELETE /session-key/` | ID parameter is ignored in legacy endpoint. New endpoint always operates on current user. |

**Important Notes:**
- All legacy session key endpoints with `{id}` always operate on the current authenticated user, regardless of the ID provided
- The `/activate-user-key/` endpoint accepts either `user_keys` or `user_key_ids` in the request body for backward compatibility

### Removed Endpoints

The following endpoints have been **permanently removed**:

- **POST /get-session-key/** - Replaced by `POST /session-key/`

If you are still using removed endpoints, update your integration immediately to use the current API.
