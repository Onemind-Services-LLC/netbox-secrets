"""
Zero-knowledge secret sharing models using Tenant as the group boundary.

Architecture:
- Tenant = Group (uses NetBox's existing Tenant model)
- TenantCryptoKey: Each tenant has a symmetric encryption key, encrypted to each member
- TenantMembership: Links users to tenants with their encrypted copy of tenant key
- TenantServiceAccount: Non-human accounts for automation
- ServiceAccountActivation: In-memory store for activated service accounts (lost on restart)
- TenantSecret: Secrets encrypted with tenant key (server never sees plaintext)

Security model:
- All encryption happens client-side (browser JavaScript)
- Server only stores ciphertext
- Even NetBox superadmins cannot decrypt secrets
- Service accounts require human activation after each restart
"""
import secrets
import threading
from datetime import datetime

from django.conf import settings
from django.db import models
from django.urls import reverse

from netbox.models import NetBoxModel


__all__ = [
    'TenantMembership',
    'TenantServiceAccount',
    'ServiceAccountActivation',
    'TenantSecret',
]


class TenantMembership(NetBoxModel):
    """
    Links a user to a Tenant with their encrypted copy of the tenant's encryption key.

    The tenant_key is a symmetric key (AES-256) that encrypts all secrets for the tenant.
    Each member has their own copy, encrypted with their X25519 public key.
    Only they can decrypt it using their private key (protected by Passkey/Touch ID).

    Security model:
    - tenant_key generated client-side, never sent to server in plaintext
    - encrypted_tenant_key can only be decrypted by the member's private key
    - Private key protected by WebAuthn Passkey (Touch ID / Face ID)
    """

    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey(
        to='tenancy.Tenant',
        on_delete=models.CASCADE,
        related_name='crypto_memberships',
    )
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='tenant_crypto_memberships',
    )

    # The user's X25519 public key (for encrypting tenant key to this user)
    public_key = models.TextField(
        help_text='X25519 public key in PEM format',
    )

    # WebAuthn credential ID for this user's Passkey
    webauthn_credential_id = models.CharField(
        max_length=512,
        help_text='WebAuthn credential ID (base64url encoded)',
    )

    # The user's X25519 private key, encrypted with their WebAuthn PRF key
    # This allows the private key to be stored server-side but only decrypted
    # by the user's Passkey
    encrypted_private_key = models.BinaryField(
        max_length=256,
        help_text='X25519 private key encrypted with WebAuthn PRF-derived key',
    )

    # The tenant's encryption key, encrypted with this user's X25519 public key
    encrypted_tenant_key = models.BinaryField(
        max_length=256,
        help_text='Tenant key encrypted with member\'s X25519 public key (SealedBox)',
    )

    # Role within the tenant's secret management
    ROLE_MEMBER = 'member'
    ROLE_ADMIN = 'admin'
    ROLE_CHOICES = [
        (ROLE_MEMBER, 'Member'),
        (ROLE_ADMIN, 'Admin'),
    ]
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ROLE_MEMBER,
    )

    # Audit: who added this member
    added_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='added_tenant_memberships',
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ['tenant', 'user']
        unique_together = [['tenant', 'user']]
        verbose_name = 'Tenant Crypto Membership'
        verbose_name_plural = 'Tenant Crypto Memberships'

    def __str__(self):
        return f"{self.user} in {self.tenant}"

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:tenantmembership', args=[self.pk])

    def is_admin(self):
        return self.role == self.ROLE_ADMIN


class TenantServiceAccount(NetBoxModel):
    """
    A non-human account for automated access to tenant secrets.

    Service accounts have an X25519 keypair for decrypting the tenant key.
    However, their private key is stored encrypted, and the decryption key
    (activation_key) is ONLY held in memory after human activation.

    On NetBox restart:
    - Memory is cleared
    - All service accounts become inactive
    - Human must re-activate each service account

    This ensures that even if the database is compromised, automated access
    requires a human to explicitly authorize it.
    """

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    tenant = models.ForeignKey(
        to='tenancy.Tenant',
        on_delete=models.CASCADE,
        related_name='crypto_service_accounts',
    )

    # X25519 public key (can be shared, stored in plaintext)
    public_key = models.TextField(
        help_text='X25519 public key in PEM format',
    )

    # X25519 private key encrypted with activation_key
    # The activation_key exists only in memory after human activation
    encrypted_private_key = models.BinaryField(
        max_length=256,
        help_text='X25519 private key encrypted with activation key (AES-256-GCM)',
    )

    # The tenant key encrypted to this service account's X25519 public key
    encrypted_tenant_key = models.BinaryField(
        max_length=256,
        help_text='Tenant key encrypted with service account\'s X25519 public key',
    )

    # Salt for activation key derivation (stored in DB, not secret)
    activation_salt = models.BinaryField(
        max_length=32,
        help_text='Salt for activation key derivation',
    )

    # Nonce used when encrypting the private key (needed for decryption)
    private_key_nonce = models.BinaryField(
        max_length=12,
        help_text='AES-GCM nonce for private key encryption',
    )

    # API token for service account authentication
    token = models.CharField(
        max_length=64,
        unique=True,
        help_text='API token for service account authentication',
    )
    token_last_used = models.DateTimeField(null=True, blank=True)

    # Whether this service account is enabled (can be disabled by admin)
    enabled = models.BooleanField(default=True)

    # Audit: last activation
    last_activated = models.DateTimeField(null=True, blank=True)
    last_activated_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='activated_tenant_service_accounts',
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ['tenant', 'name']
        unique_together = [['tenant', 'name']]
        verbose_name = 'Tenant Service Account'
        verbose_name_plural = 'Tenant Service Accounts'

    def __str__(self):
        return f"{self.name} ({self.tenant})"

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:tenantserviceaccount', args=[self.pk])

    @property
    def is_active(self):
        """Check if this service account is currently activated (has in-memory key)."""
        return ServiceAccountActivation.is_activated(self.id)

    def generate_token(self):
        """Generate a new API token for this service account."""
        self.token = f"nbsvc_{secrets.token_urlsafe(48)}"
        return self.token

    def save(self, *args, **kwargs):
        if not self.token:
            self.generate_token()
        if not self.activation_salt:
            self.activation_salt = secrets.token_bytes(32)
        super().save(*args, **kwargs)


class ServiceAccountActivation:
    """
    In-memory store for activated service account keys.

    CRITICAL: This data exists ONLY in memory and is lost on process restart.
    This is intentional - it ensures that automated access requires human
    authorization after each restart.

    Thread-safe implementation using a lock.

    Usage:
        # Activate (after human authorization via Passkey)
        ServiceAccountActivation.activate(sa_id, decrypted_private_key, user_id)

        # Check if active
        if ServiceAccountActivation.is_activated(sa_id):
            key = ServiceAccountActivation.get_private_key(sa_id)

        # Deactivate
        ServiceAccountActivation.deactivate(sa_id)
    """

    # Class-level storage - intentionally not persisted
    _activations: dict[int, dict] = {}
    _lock = threading.Lock()

    @classmethod
    def activate(cls, service_account_id: int, decrypted_private_key: bytes, activated_by_user_id: int) -> None:
        """
        Store the decrypted private key for a service account.

        Args:
            service_account_id: The service account's database ID
            decrypted_private_key: The decrypted X25519 private key (32 bytes)
            activated_by_user_id: The user who activated this service account
        """
        if len(decrypted_private_key) != 32:
            raise ValueError("X25519 private key must be exactly 32 bytes")

        with cls._lock:
            cls._activations[service_account_id] = {
                'private_key': decrypted_private_key,
                'activated_at': datetime.now(),
                'activated_by': activated_by_user_id,
            }

        # Update the database record
        from .groups import TenantServiceAccount
        TenantServiceAccount.objects.filter(id=service_account_id).update(
            last_activated=datetime.now(),
            last_activated_by_id=activated_by_user_id,
        )

    @classmethod
    def deactivate(cls, service_account_id: int) -> None:
        """Remove the activation for a service account."""
        with cls._lock:
            cls._activations.pop(service_account_id, None)

    @classmethod
    def deactivate_all(cls) -> None:
        """Remove all activations (security lockdown)."""
        with cls._lock:
            cls._activations.clear()

    @classmethod
    def deactivate_for_tenant(cls, tenant_id: int) -> int:
        """Deactivate all service accounts for a tenant. Returns count deactivated."""
        from .groups import TenantServiceAccount
        sa_ids = list(TenantServiceAccount.objects.filter(tenant_id=tenant_id).values_list('id', flat=True))
        count = 0
        with cls._lock:
            for sa_id in sa_ids:
                if sa_id in cls._activations:
                    del cls._activations[sa_id]
                    count += 1
        return count

    @classmethod
    def is_activated(cls, service_account_id: int) -> bool:
        """Check if a service account is currently activated."""
        with cls._lock:
            return service_account_id in cls._activations

    @classmethod
    def get_private_key(cls, service_account_id: int) -> bytes | None:
        """
        Get the decrypted private key for a service account.

        Returns None if the service account is not activated.
        """
        with cls._lock:
            activation = cls._activations.get(service_account_id)
            if activation:
                return activation['private_key']
            return None

    @classmethod
    def get_activation_info(cls, service_account_id: int) -> dict | None:
        """Get activation metadata for a service account."""
        with cls._lock:
            activation = cls._activations.get(service_account_id)
            if activation:
                return {
                    'activated_at': activation['activated_at'],
                    'activated_by': activation['activated_by'],
                }
            return None

    @classmethod
    def get_all_activated_ids(cls) -> list[int]:
        """Get list of all activated service account IDs."""
        with cls._lock:
            return list(cls._activations.keys())

    @classmethod
    def count_activated(cls) -> int:
        """Get count of activated service accounts."""
        with cls._lock:
            return len(cls._activations)


class TenantSecret(NetBoxModel):
    """
    A secret encrypted with the tenant's key.

    ALL encryption/decryption happens client-side (browser JavaScript).
    The server ONLY stores ciphertext and cannot decrypt.

    Security guarantees:
    - Plaintext never sent to server
    - Tenant key never sent to server
    - NetBox admins cannot read secrets
    - Database dump reveals only ciphertext

    Encryption format: AES-256-GCM
    - ciphertext = nonce (12 bytes) || encrypted_data || auth_tag (16 bytes)
    """

    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey(
        to='tenancy.Tenant',
        on_delete=models.CASCADE,
        related_name='crypto_secrets',
    )
    name = models.CharField(max_length=100)
    description = models.TextField(
        blank=True,
        help_text='Description (stored in plaintext - do not include sensitive data)',
    )

    # The encrypted secret (AES-256-GCM with tenant key)
    # Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    ciphertext = models.BinaryField(
        max_length=65600,
        help_text='AES-256-GCM encrypted secret data',
    )

    # Optional: encrypted TOTP seed
    totp_ciphertext = models.BinaryField(
        max_length=256,
        blank=True,
        null=True,
        help_text='Encrypted TOTP seed (same encryption as main secret)',
    )
    totp_issuer = models.CharField(max_length=100, blank=True)
    totp_digits = models.PositiveSmallIntegerField(default=6)
    totp_period = models.PositiveSmallIntegerField(default=30)

    # Optional link to a NetBox object (similar to original Secret model)
    assigned_object_type = models.ForeignKey(
        to='contenttypes.ContentType',
        on_delete=models.SET_NULL,
        related_name='tenant_secrets',
        blank=True,
        null=True,
    )
    assigned_object_id = models.PositiveIntegerField(blank=True, null=True)

    # Metadata - NOT encrypted, visible to anyone with DB access
    # Use only for non-sensitive categorization
    metadata = models.JSONField(
        blank=True,
        null=True,
        help_text='Optional metadata (NOT encrypted - do not include sensitive data)',
    )

    # Audit fields
    created_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_tenant_secrets',
        null=True,
        blank=True,
    )
    last_modified_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='modified_tenant_secrets',
        null=True,
        blank=True,
    )
    last_accessed = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Last time this secret was decrypted',
    )
    access_count = models.PositiveIntegerField(
        default=0,
        help_text='Number of times this secret has been accessed',
    )

    class Meta:
        ordering = ['tenant', 'name']
        unique_together = [['tenant', 'name']]
        verbose_name = 'Tenant Secret'
        verbose_name_plural = 'Tenant Secrets'

    def __str__(self):
        return f"{self.name} ({self.tenant})"

    def get_absolute_url(self):
        return reverse('plugins:netbox_secrets:tenantsecret', args=[self.pk])

    @property
    def has_totp(self):
        return self.totp_ciphertext is not None

    def record_access(self, user=None):
        """Record that this secret was accessed."""
        from django.utils import timezone
        self.last_accessed = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed', 'access_count'])
