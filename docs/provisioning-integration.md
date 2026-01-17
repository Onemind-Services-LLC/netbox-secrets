# Provisioning Integration Guide

This guide explains how to integrate the NetBox Secrets plugin with automation and provisioning systems.

## Overview

The zero-knowledge tenant crypto system provides secure secret storage with these key features:

- **End-to-end encryption**: Secrets are encrypted client-side; the server never sees plaintext
- **Tenant-based access control**: Secrets are grouped by NetBox Tenant
- **Service accounts**: Non-human accounts for automation that require human activation
- **Memory-only keys**: Service account private keys exist only in server memory (lost on restart)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetBox Server                             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   netbox-secrets plugin                  │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │    │
│  │  │TenantSecret  │  │ServiceAccount│  │ Activation   │   │    │
│  │  │(ciphertext)  │  │(encrypted)   │  │(memory only) │   │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              │ REST API                          │
└──────────────────────────────│───────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Provisioning  │    │ Ansible/      │    │ Custom        │
│ Plugin        │    │ Scripts       │    │ Automation    │
└───────────────┘    └───────────────┘    └───────────────┘
```

## Setup

### 1. Create a Service Account

Service accounts are created by tenant admins via the web UI or API.

**Via Web UI:**
1. Navigate to Secrets → Service Accounts
2. Click "Add Service Account"
3. Select the tenant and provide a name
4. The system generates an API token and encryption keys

**Via API:**
```python
import requests

response = requests.post(
    'https://netbox.example.com/api/plugins/netbox_secrets/tenant-service-accounts/',
    headers={'Authorization': 'Token <user-api-token>'},
    json={
        'tenant': 1,
        'name': 'provisioning-service',
        'description': 'Service account for automated provisioning',
        'public_key': '<generated-x25519-public-key>',
        'encrypted_private_key': '<base64>',
        'encrypted_tenant_key': '<base64>',
        'activation_salt': '<base64>',
        'private_key_nonce': '<base64>',
    }
)
```

### 2. Activate the Service Account

After creating the service account (or after any NetBox restart), a human must activate it using their Passkey.

**Via Web UI:**
1. Navigate to Secrets → Service Accounts
2. Click on the service account
3. Click "Activate" button
4. Authenticate with your Passkey
5. The service account's private key is now in server memory

**Via API:**
```python
# This requires the decrypted private key from the activation process
response = requests.post(
    'https://netbox.example.com/api/plugins/netbox_secrets/service-account-activation/',
    headers={'Authorization': 'Token <admin-api-token>'},
    json={
        'service_account_id': 1,
        'decrypted_private_key': '<base64-encoded-32-byte-key>',
    }
)
```

### 3. Use the Service Account

Once activated, use the service account token to access secrets.

## Python Client Library

The plugin includes a Python client library for easy integration.

### Installation

The client is part of the netbox-secrets package:

```python
from netbox_secrets.client import SecretsClient, LocalSecretsClient
```

### Remote Usage (HTTP API)

Use `SecretsClient` when connecting from external systems:

```python
from netbox_secrets.client import (
    SecretsClient,
    NotActivatedError,
    SecretNotFoundError,
)

# Initialize client with service account token
client = SecretsClient(
    base_url='https://netbox.example.com',
    token='your-service-account-token'
)

# List available secrets
secrets = client.list_secrets()
for s in secrets:
    print(f"{s.name}: {s.description} (TOTP: {s.has_totp})")

# Get a decrypted secret (server-side decryption)
try:
    secret = client.get_secret('database-password')
    print(f"Password: {secret.plaintext}")

    # If the secret has TOTP, you also get the current code
    if secret.has_totp:
        print(f"TOTP Code: {secret.totp_code}")
        print(f"TOTP Seed: {secret.totp_seed}")  # For manual code generation

except NotActivatedError:
    print("Service account needs activation - ask an admin")
except SecretNotFoundError:
    print("Secret not found")
```

### Local Usage (Within NetBox)

Use `LocalSecretsClient` when running in the NetBox process (e.g., provisioning plugin, management commands):

```python
from netbox_secrets.client import LocalSecretsClient, NotActivatedError

# Initialize with service account ID (not token)
client = LocalSecretsClient(service_account_id=1)

try:
    # Get a secret directly from the database
    secret = client.get_secret('api-key')
    print(f"API Key: {secret.plaintext}")
except NotActivatedError:
    print("Service account needs activation")
```

### Client-Side Decryption

For maximum security, retrieve encrypted data and decrypt locally:

```python
from netbox_secrets.client import SecretsClient

client = SecretsClient(base_url='https://netbox.example.com', token='...')

# Get encrypted secret (no server-side decryption)
encrypted = client.get_secret_encrypted('database-password')

# Decrypt locally (requires private key)
# This is useful if you have the private key in a secure enclave/HSM
private_key = load_from_secure_storage()  # 32-byte X25519 key
secret = SecretsClient.decrypt_locally(encrypted, private_key)
print(secret.plaintext)
```

## REST API Reference

### Authentication

All service account endpoints use Bearer token authentication:

```
Authorization: Bearer <service-account-token>
```

### Endpoints

#### List Secrets
```
GET /api/plugins/netbox_secrets/svc/secrets/
```

Response:
```json
[
  {
    "id": 1,
    "name": "database-password",
    "description": "Production DB credentials",
    "has_totp": false
  },
  {
    "id": 2,
    "name": "api-service-account",
    "description": "API with 2FA",
    "has_totp": true
  }
]
```

#### Get Encrypted Secret
```
GET /api/plugins/netbox_secrets/svc/secrets/{id}/
```

Response:
```json
{
  "id": 1,
  "name": "database-password",
  "ciphertext": "<base64-encoded-aes-gcm>",
  "encrypted_tenant_key": "<base64-encoded-x25519>",
  "has_totp": false,
  "totp_ciphertext": null
}
```

#### Decrypt Secret (Server-Side)
```
POST /api/plugins/netbox_secrets/svc/secrets/{id}/decrypt/
```

Response:
```json
{
  "id": 1,
  "name": "database-password",
  "plaintext": "super-secret-password",
  "totp_seed": "JBSWY3DPEHPK3PXP",
  "totp_code": "123456"
}
```

### Error Responses

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `Invalid or missing token` | Token not provided or invalid |
| 403 | `Service account not activated` | Human must activate the account |
| 403 | `Service account is disabled` | Account has been disabled by admin |
| 404 | `Secret not found` | Secret doesn't exist or wrong tenant |

## Provisioning Plugin Integration

### Example: netbox-provisioning integration

```python
# In netbox_provisioning/services/credentials.py

from netbox_secrets.client import LocalSecretsClient, NotActivatedError

class CredentialService:
    """Service for retrieving credentials for provisioning operations."""

    def __init__(self, service_account_id: int):
        self.client = LocalSecretsClient(service_account_id)

    def get_vcenter_credentials(self) -> dict:
        """Get VMware vCenter credentials."""
        try:
            username = self.client.get_secret('vcenter-username')
            password = self.client.get_secret('vcenter-password')
            return {
                'username': username.plaintext,
                'password': password.plaintext,
            }
        except NotActivatedError:
            raise RuntimeError(
                "Provisioning service account not activated. "
                "An admin must activate it from the web UI."
            )

    def get_api_key_with_totp(self, secret_name: str) -> tuple[str, str]:
        """Get an API key that requires TOTP."""
        secret = self.client.get_secret(secret_name)
        if not secret.has_totp:
            raise ValueError(f"Secret {secret_name} does not have TOTP")
        return secret.plaintext, secret.totp_code
```

### Example: Ansible Integration

```yaml
# playbooks/provision_vm.yml

- name: Get credentials from NetBox Secrets
  uri:
    url: "{{ netbox_url }}/api/plugins/netbox_secrets/svc/secrets/{{ item }}/decrypt/"
    method: POST
    headers:
      Authorization: "Bearer {{ service_account_token }}"
    status_code: 200
  register: secrets
  loop:
    - vcenter-password
    - deploy-key
  no_log: true

- name: Provision VM
  vmware_guest:
    hostname: "{{ vcenter_host }}"
    username: "{{ vcenter_user }}"
    password: "{{ secrets.results[0].json.plaintext }}"
    # ...
```

## Security Considerations

### Human Activation Requirement

Service accounts require human activation after:
- Initial creation
- NetBox service restart
- Explicit deactivation

This ensures that automated access can be revoked by simply restarting NetBox.

### Memory-Only Storage

The decrypted private key exists only in server memory:
- Never written to disk
- Lost on process restart
- Cleared on explicit deactivation

### Tenant Isolation

Service accounts can only access secrets within their assigned tenant. The tenant key (AES-256) is encrypted with the service account's X25519 public key.

### Audit Trail

All secret access is logged:
- `last_accessed` timestamp on TenantSecret
- `access_count` counter
- `token_last_used` on service account

### Token Security

- Tokens are 64-character random strings
- Use HTTPS in production
- Rotate tokens periodically
- Store tokens securely (not in code)

## Troubleshooting

### "Service account not activated"

A human admin needs to activate the service account:
1. Log into NetBox web UI
2. Go to Secrets → Service Accounts
3. Click on the account
4. Click "Activate" and use Passkey

### "Invalid or missing token"

- Check the token is correct
- Ensure you're using Bearer authentication
- Verify the service account hasn't been deleted

### "Secret not found"

- The secret may not exist
- The secret may be in a different tenant
- Check the exact name (case-sensitive)

### Decryption Errors

- Service account activation may have expired
- Tenant key may have been rotated
- Database corruption (rare)
