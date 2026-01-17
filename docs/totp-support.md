# TOTP (2FA) Support

This fork of netbox-secrets adds support for storing TOTP (Time-based One-Time Password) seeds alongside secrets. This enables storing complete credential sets including 2FA seeds for automated access.

## Overview

TOTP is the standard behind authenticator apps like Google Authenticator, Microsoft Authenticator, and Authy. By storing the TOTP seed alongside the password, you can enable automated systems to perform complete authentication including 2FA.

## How It Works

1. **Storage**: TOTP seeds are encrypted with the same AES-256-CFB cipher as regular secrets
2. **Validation**: A SHA-256 hash validates the decrypted seed
3. **Generation**: The `pyotp` library generates current TOTP codes
4. **Provisioning**: Generate QR code URIs for authenticator app setup

## Adding TOTP to a Secret

### Via Web UI

When creating or editing a secret:

1. Navigate to the "TOTP (2FA)" section
2. Enter the **TOTP Seed** (base32-encoded, e.g., `JBSWY3DPEHPK3PXP`)
3. Confirm by entering it again
4. Optionally set:
   - **Issuer**: Service name (e.g., "AWS", "GitHub")
   - **Digits**: Code length (default: 6)
   - **Period**: Refresh interval in seconds (default: 30)

### Via API

```python
import requests

response = requests.post(
    'https://netbox.example.com/api/plugins/secrets/secrets/',
    headers={
        'Authorization': 'Token YOUR_TOKEN',
        'X-Session-Key': 'YOUR_SESSION_KEY',
    },
    json={
        'assigned_object_type': 'dcim.device',
        'assigned_object_id': 123,
        'role': 1,
        'name': 'Admin Credentials',
        'plaintext': 'MySecurePassword123',
        'totp_plaintext': 'JBSWY3DPEHPK3PXP',
        'totp_issuer': 'MyService',
        'totp_digits': 6,
        'totp_period': 30,
    }
)
```

## Retrieving TOTP Codes

### Via Python API Client

```python
from netbox_secrets.models import Secret

# Get and decrypt the secret
secret = Secret.objects.get(pk=123)
secret.decrypt(master_key)

# Check if TOTP is configured
if secret.has_totp:
    # Get current TOTP code
    code = secret.get_totp_code()
    print(f"Current TOTP code: {code}")

    # Verify a code
    is_valid = secret.verify_totp_code("123456")

    # Get provisioning URI for QR code
    uri = secret.get_totp_provisioning_uri(account_name="admin@example.com")
```

### Via REST API

The API returns TOTP-related data when a secret is decrypted:

```json
{
    "id": 123,
    "name": "Admin Credentials",
    "plaintext": "MySecurePassword123",
    "has_totp": true,
    "totp_code": "123456",
    "totp_provisioning_uri": "otpauth://totp/MyService:admin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyService&digits=6&period=30"
}
```

## TOTP Configuration Options

| Field | Default | Description |
|-------|---------|-------------|
| `totp_issuer` | "NetBox" | Service name shown in authenticator apps |
| `totp_digits` | 6 | Number of digits in the code (6 or 8) |
| `totp_period` | 30 | Seconds between code refreshes |

## Generating QR Codes

The provisioning URI can be converted to a QR code:

```python
import qrcode

secret.decrypt(master_key)
uri = secret.get_totp_provisioning_uri("admin@example.com")

# Generate QR code
img = qrcode.make(uri)
img.save("totp_qr.png")
```

## Base32 Encoding

TOTP seeds must be base32-encoded. If you have a raw secret:

```python
import base64
import os

# Generate a random 20-byte secret
raw_secret = os.urandom(20)

# Encode as base32
totp_seed = base64.b32encode(raw_secret).decode('utf-8')
print(f"TOTP seed: {totp_seed}")
```

## Security Considerations

1. **TOTP seeds are high-value secrets** - treat them with the same care as passwords
2. **Storing TOTP seeds reduces 2FA effectiveness** - only do this when necessary for automation
3. **Consider access controls** - restrict who can view secrets with TOTP seeds
4. **Audit access** - NetBox logs all secret access
5. **Rotation** - rotate TOTP seeds periodically if possible

## Use Cases

1. **Automated deployments** - systems that need to authenticate with 2FA-protected services
2. **Disaster recovery** - backup storage of 2FA seeds
3. **Team credential sharing** - shared service accounts with 2FA
4. **Integration testing** - automated tests against 2FA-protected APIs
