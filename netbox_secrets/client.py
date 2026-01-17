"""
NetBox Secrets Client Library for Service Account Integration.

This module provides a Python client for consuming secrets via service accounts.
It's designed to be used by the netbox-provisioning plugin and other automation tools.

Usage:
    from netbox_secrets.client import SecretsClient

    # Initialize client with service account token
    client = SecretsClient(
        base_url='https://netbox.example.com',
        token='your-service-account-token'
    )

    # List available secrets
    secrets = client.list_secrets()

    # Get a decrypted secret
    secret = client.get_secret('database-password')
    print(secret.plaintext)

    # Get TOTP code if available
    if secret.has_totp:
        print(secret.totp_code)
"""

import base64
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from nacl.public import PrivateKey, SealedBox
    from Crypto.Cipher import AES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


logger = logging.getLogger(__name__)


@dataclass
class SecretMetadata:
    """Metadata about a secret (without decrypted content)."""
    id: int
    name: str
    description: str
    has_totp: bool


@dataclass
class DecryptedSecret:
    """A decrypted secret with optional TOTP."""
    id: int
    name: str
    plaintext: str
    has_totp: bool
    totp_seed: Optional[str] = None
    totp_code: Optional[str] = None


@dataclass
class EncryptedSecret:
    """An encrypted secret for client-side decryption."""
    id: int
    name: str
    ciphertext: bytes
    encrypted_tenant_key: bytes
    has_totp: bool
    totp_ciphertext: Optional[bytes] = None


class SecretsClientError(Exception):
    """Base exception for secrets client errors."""
    pass


class AuthenticationError(SecretsClientError):
    """Raised when authentication fails."""
    pass


class NotActivatedError(SecretsClientError):
    """Raised when service account is not activated."""
    pass


class SecretNotFoundError(SecretsClientError):
    """Raised when a secret is not found."""
    pass


class SecretsClient:
    """
    Client for consuming secrets via service account authentication.

    This client supports two decryption modes:
    1. Server-side decryption (simpler, requires trust in server)
    2. Client-side decryption (more secure, requires private key)

    For most provisioning use cases, server-side decryption is recommended
    since the service account private key is already in server memory.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        """
        Initialize the secrets client.

        Args:
            base_url: NetBox base URL (e.g., 'https://netbox.example.com')
            token: Service account API token
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is required: pip install requests")

        self.base_url = base_url.rstrip('/')
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })

    def _url(self, path: str) -> str:
        """Build full URL for API endpoint."""
        return urljoin(self.base_url, f'/api/plugins/netbox_secrets/svc/secrets/{path}')

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request and handle errors."""
        url = self._url(path)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)

        try:
            response = self._session.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            raise SecretsClientError(f"Request failed: {e}")

        if response.status_code == 401:
            raise AuthenticationError("Invalid or missing token")
        if response.status_code == 403:
            error = response.json().get('error', 'Access denied')
            if 'not activated' in error.lower():
                raise NotActivatedError(error)
            raise SecretsClientError(error)
        if response.status_code == 404:
            raise SecretNotFoundError("Secret not found")
        if not response.ok:
            try:
                error = response.json().get('error', response.text)
            except ValueError:
                error = response.text
            raise SecretsClientError(f"API error ({response.status_code}): {error}")

        return response.json()

    def list_secrets(self) -> List[SecretMetadata]:
        """
        List all secrets available to this service account.

        Returns:
            List of SecretMetadata objects
        """
        data = self._request('GET', '')
        return [
            SecretMetadata(
                id=s['id'],
                name=s['name'],
                description=s.get('description', ''),
                has_totp=s.get('has_totp', False),
            )
            for s in data
        ]

    def get_secret(self, name_or_id: str | int) -> DecryptedSecret:
        """
        Get a decrypted secret by name or ID.

        Uses server-side decryption. The service account must be activated.

        Args:
            name_or_id: Secret name or numeric ID

        Returns:
            DecryptedSecret with plaintext value
        """
        # If name provided, find ID first
        if isinstance(name_or_id, str):
            secrets = self.list_secrets()
            matches = [s for s in secrets if s.name == name_or_id]
            if not matches:
                raise SecretNotFoundError(f"Secret '{name_or_id}' not found")
            secret_id = matches[0].id
        else:
            secret_id = name_or_id

        data = self._request('POST', f'{secret_id}/decrypt/')
        return DecryptedSecret(
            id=data['id'],
            name=data['name'],
            plaintext=data['plaintext'],
            has_totp=bool(data.get('totp_seed')),
            totp_seed=data.get('totp_seed'),
            totp_code=data.get('totp_code'),
        )

    def get_secret_encrypted(self, name_or_id: str | int) -> EncryptedSecret:
        """
        Get an encrypted secret for client-side decryption.

        Use this if you want to decrypt secrets locally instead of
        trusting the server with plaintext.

        Args:
            name_or_id: Secret name or numeric ID

        Returns:
            EncryptedSecret with ciphertext
        """
        # If name provided, find ID first
        if isinstance(name_or_id, str):
            secrets = self.list_secrets()
            matches = [s for s in secrets if s.name == name_or_id]
            if not matches:
                raise SecretNotFoundError(f"Secret '{name_or_id}' not found")
            secret_id = matches[0].id
        else:
            secret_id = name_or_id

        data = self._request('GET', f'{secret_id}/')
        return EncryptedSecret(
            id=data['id'],
            name=data['name'],
            ciphertext=base64.b64decode(data['ciphertext']),
            encrypted_tenant_key=base64.b64decode(data['encrypted_tenant_key']),
            has_totp=data.get('has_totp', False),
            totp_ciphertext=base64.b64decode(data['totp_ciphertext']) if data.get('totp_ciphertext') else None,
        )

    @staticmethod
    def decrypt_locally(
        encrypted: EncryptedSecret,
        private_key: bytes
    ) -> DecryptedSecret:
        """
        Decrypt a secret locally using the service account's private key.

        This requires the private key to be available locally (e.g., from
        a secure enclave or HSM). For most use cases, server-side decryption
        via get_secret() is simpler and equally secure.

        Args:
            encrypted: EncryptedSecret from get_secret_encrypted()
            private_key: 32-byte X25519 private key

        Returns:
            DecryptedSecret with plaintext value
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "Crypto libraries required for local decryption: "
                "pip install pynacl pycryptodome"
            )

        # Decrypt tenant key using X25519 private key
        priv_key = PrivateKey(private_key)
        sealed_box = SealedBox(priv_key)
        tenant_key = sealed_box.decrypt(encrypted.encrypted_tenant_key)

        # Decrypt secret using tenant key (AES-256-GCM)
        nonce = encrypted.ciphertext[:12]
        ciphertext_with_tag = encrypted.ciphertext[12:]
        cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(
            ciphertext_with_tag[:-16],
            ciphertext_with_tag[-16:]
        )

        result = DecryptedSecret(
            id=encrypted.id,
            name=encrypted.name,
            plaintext=plaintext.decode('utf-8'),
            has_totp=encrypted.has_totp,
        )

        # Decrypt TOTP if present
        if encrypted.totp_ciphertext:
            totp_nonce = encrypted.totp_ciphertext[:12]
            totp_ct_with_tag = encrypted.totp_ciphertext[12:]
            totp_cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=totp_nonce)
            totp_plaintext = totp_cipher.decrypt_and_verify(
                totp_ct_with_tag[:-16],
                totp_ct_with_tag[-16:]
            )
            result.totp_seed = totp_plaintext.decode('utf-8')

            # Generate current TOTP code
            try:
                import pyotp
                totp = pyotp.TOTP(result.totp_seed)
                result.totp_code = totp.now()
            except ImportError:
                pass  # pyotp not installed, skip TOTP code generation

        return result


class LocalSecretsClient:
    """
    Client for accessing secrets when running within NetBox process.

    Use this when your code runs in the same process as NetBox (e.g., custom
    scripts, management commands, or the provisioning plugin).

    This avoids HTTP overhead and directly accesses the models.
    """

    def __init__(self, service_account_id: int):
        """
        Initialize local client.

        Args:
            service_account_id: ID of the TenantServiceAccount
        """
        self.service_account_id = service_account_id
        self._sa = None
        self._tenant_key = None

    def _load_service_account(self):
        """Load and validate service account."""
        if self._sa is not None:
            return

        from netbox_secrets.models import TenantServiceAccount, ServiceAccountActivation

        try:
            self._sa = TenantServiceAccount.objects.get(pk=self.service_account_id)
        except TenantServiceAccount.DoesNotExist:
            raise SecretsClientError(f"Service account {self.service_account_id} not found")

        if not self._sa.enabled:
            raise SecretsClientError("Service account is disabled")

        if not ServiceAccountActivation.is_active(self.service_account_id):
            raise NotActivatedError(
                "Service account not activated. A human must activate it first."
            )

    def _get_tenant_key(self) -> bytes:
        """Get decrypted tenant key."""
        if self._tenant_key is not None:
            return self._tenant_key

        self._load_service_account()

        from netbox_secrets.models import ServiceAccountActivation

        private_key = ServiceAccountActivation.get_private_key(self.service_account_id)
        if not private_key:
            raise NotActivatedError("Service account activation expired")

        if not CRYPTO_AVAILABLE:
            raise ImportError("pynacl required: pip install pynacl")

        # Decrypt tenant key
        from nacl.public import PrivateKey, SealedBox
        priv_key = PrivateKey(private_key)
        sealed_box = SealedBox(priv_key)
        self._tenant_key = sealed_box.decrypt(bytes(self._sa.encrypted_tenant_key))

        return self._tenant_key

    def list_secrets(self) -> List[SecretMetadata]:
        """List all secrets in this tenant."""
        self._load_service_account()

        from netbox_secrets.models import TenantSecret

        secrets = TenantSecret.objects.filter(tenant=self._sa.tenant)
        return [
            SecretMetadata(
                id=s.id,
                name=s.name,
                description=s.description,
                has_totp=s.has_totp,
            )
            for s in secrets
        ]

    def get_secret(self, name_or_id: str | int) -> DecryptedSecret:
        """
        Get a decrypted secret.

        Args:
            name_or_id: Secret name or numeric ID

        Returns:
            DecryptedSecret with plaintext value
        """
        self._load_service_account()

        from netbox_secrets.models import TenantSecret

        if isinstance(name_or_id, str):
            try:
                secret = TenantSecret.objects.get(
                    tenant=self._sa.tenant,
                    name=name_or_id
                )
            except TenantSecret.DoesNotExist:
                raise SecretNotFoundError(f"Secret '{name_or_id}' not found")
        else:
            try:
                secret = TenantSecret.objects.get(
                    pk=name_or_id,
                    tenant=self._sa.tenant
                )
            except TenantSecret.DoesNotExist:
                raise SecretNotFoundError(f"Secret {name_or_id} not found")

        tenant_key = self._get_tenant_key()

        # Decrypt secret
        from Crypto.Cipher import AES
        ciphertext = bytes(secret.ciphertext)
        nonce = ciphertext[:12]
        ct_with_tag = ciphertext[12:]
        cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct_with_tag[:-16], ct_with_tag[-16:])

        result = DecryptedSecret(
            id=secret.id,
            name=secret.name,
            plaintext=plaintext.decode('utf-8'),
            has_totp=secret.has_totp,
        )

        # Decrypt TOTP if present
        if secret.totp_ciphertext:
            totp_ct = bytes(secret.totp_ciphertext)
            totp_nonce = totp_ct[:12]
            totp_ct_with_tag = totp_ct[12:]
            totp_cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=totp_nonce)
            totp_plaintext = totp_cipher.decrypt_and_verify(
                totp_ct_with_tag[:-16],
                totp_ct_with_tag[-16:]
            )
            result.totp_seed = totp_plaintext.decode('utf-8')

            try:
                import pyotp
                totp = pyotp.TOTP(
                    result.totp_seed,
                    digits=secret.totp_digits,
                    interval=secret.totp_period,
                )
                result.totp_code = totp.now()
            except ImportError:
                pass

        # Record access
        secret.record_access()

        return result
