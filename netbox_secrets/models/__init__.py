"""
NetBox Secrets Plugin Models.

This package contains all models for the NetBox Secrets plugin:

Key Management (keys.py):
- UserKey: RSA public key storage and master key encryption
- SessionKey: Temporary session keys for secret encryption/decryption

Secret Storage (secrets.py):
- SecretRole: Functional classification of secrets
- Secret: AES-256 encrypted storage for sensitive data
"""

from .keys import SessionKey, UserKey
from .secrets import Secret, SecretRole

__all__ = [
    'UserKey',
    'SessionKey',
    'SecretRole',
    'Secret',
]
