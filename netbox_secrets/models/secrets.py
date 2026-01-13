"""
Secret storage models for NetBox Secrets Plugin.

This module contains models for managing encrypted secrets:
- SecretRole: Functional classification/categorization of secrets
- Secret: Encrypted storage for sensitive data with AES-256 encryption
"""

import secrets as secrets_module
from typing import Optional

from Crypto.Cipher import AES
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from netbox.models import NestedGroupModel, PrimaryModel
from netbox.models.features import ContactsMixin
from utilities.querysets import RestrictedQuerySet
from ..hashers import SecretValidationHasher

__all__ = [
    'SecretRole',
    'Secret',
]


class SecretRole(NestedGroupModel):
    """
    Functional classification for secrets (e.g., "Login Credentials", "API Keys").

    SecretRoles provide a way to categorize and organize secrets based on their
    purpose or usage. Examples include:
    - Login Credentials
    - SNMP Communities
    - API Keys
    - SSL Certificates
    - Database Passwords

    Attributes:
        name: Descriptive name for the role
        slug: URL-friendly identifier
        description: Optional description of the role's purpose
        comments: Optional comments about the role
    """

    name = models.CharField(verbose_name=_('name'), max_length=100, unique=True, db_collation="natural_sort")
    slug = models.SlugField(verbose_name=_('slug'), max_length=100, unique=True)

    class Meta:
        ordering = ['name']
        verbose_name = _('Secret Role')
        verbose_name_plural = _('Secret Roles')

    def __str__(self):
        return self.name


class Secret(PrimaryModel, ContactsMixin):
    """
    AES-256 encrypted storage for sensitive data with cryptographic validation.

    Secrets store encrypted sensitive information such as passwords, API keys,
    certificates, and other confidential data. Each secret is:
    - Encrypted using AES-256-CFB mode
    - Validated with SHA-256 hash on decryption
    - Padded with random data to obscure plaintext length
    - Associated with any NetBox object via generic foreign key

    Features:
    - Up to 64KB of encrypted data per secret
    - Minimum 64-byte padding to protect short secrets
    - Random IV (initialization vector) for each encryption
    - Support for multiple secrets per object with different roles

    Attributes:
        assigned_object: Generic foreign key to any NetBox object
        role: Functional classification of the secret
        name: Optional descriptive name (stored as plaintext)
        ciphertext: AES-encrypted secret data with IV
        hash: SHA-256 hash for validating decrypted plaintext
        plaintext: Transient attribute containing decrypted data (not persisted)
    """

    # Encryption constants
    MAX_SECRET_SIZE = 65535  # Maximum plaintext size in bytes (64KB - 1B)
    MIN_PADDED_SIZE = 64  # Minimum padded size to obscure short secrets
    AES_BLOCK_SIZE = 16  # AES block size in bytes
    IV_SIZE = 16  # Initialization vector size in bytes

    # Generic foreign key to assigned object
    assigned_object_type = models.ForeignKey(
        to='contenttypes.ContentType',
        on_delete=models.PROTECT,
        related_name='secrets',
    )
    assigned_object_id = models.PositiveIntegerField()
    assigned_object = GenericForeignKey(ct_field='assigned_object_type', fk_field='assigned_object_id')
    _object_repr = models.CharField(
        max_length=200,
        editable=False,
        blank=True,
        null=True,
        db_index=True,
        help_text=_("Cached string representation for search"),
    )

    # Secret metadata
    role = models.ForeignKey(
        to='SecretRole',
        on_delete=models.PROTECT,
        related_name='secrets',
        help_text=_("Functional role/category of this secret"),
    )
    name = models.CharField(max_length=100, blank=True, help_text=_("Optional descriptive name for this secret"))

    # Encrypted data
    ciphertext = models.BinaryField(
        max_length=65568,  # IV (16) + length header (2) + max secret (65535) + max padding (15)
        editable=False,
        help_text=_("Encrypted secret data with IV"),
    )
    hash = models.CharField(
        max_length=128, editable=False, help_text=_("SHA-256 hash for validating decrypted plaintext")
    )

    # Transient attribute for decrypted plaintext (not persisted to database)
    plaintext: Optional[str] = None

    objects = RestrictedQuerySet.as_manager()
    clone_fields = ('role', 'assigned_object_id', 'assigned_object_type', 'tags')

    class Meta:
        ordering = ('role', 'name', 'pk')
        unique_together = (('assigned_object_type', 'assigned_object_id', 'role', 'name'),)
        verbose_name = _('Secret')
        verbose_name_plural = _('Secrets')
        indexes = [
            models.Index(fields=['assigned_object_type', 'assigned_object_id']),
            models.Index(fields=['role']),
            models.Index(fields=['_object_repr']),
        ]

    def __init__(self, *args, **kwargs):
        """
        Initialize Secret, optionally with plaintext.

        Args:
            plaintext: Optional plaintext to be encrypted on save
        """
        self.plaintext = kwargs.pop('plaintext', None)
        super().__init__(*args, **kwargs)

    def __str__(self):
        return self.name or f'Secret #{self.pk}'

    @transaction.atomic
    def save(self, *args, **kwargs):
        """
        Save the secret, caching the assigned object representation for search.
        """
        # Cache object representation for searching
        if self.assigned_object:
            self._object_repr = str(self.assigned_object)[:200]

        return super().save(*args, **kwargs)

    def _pad(self, plaintext: str) -> bytes:
        """
        Pad plaintext with length header and random bytes for AES encryption.

        Padding format:
        - 2 bytes: Big-endian plaintext length (allows up to 65535 bytes)
        - N bytes: UTF-8 encoded plaintext
        - M bytes: Random padding to reach minimum size or AES block alignment

        Minimum padded size is 64 bytes to obscure the length of short secrets,
        preventing ciphertext length analysis attacks.

        Args:
            plaintext: String to pad and prepare for encryption

        Returns:
            Padded bytes ready for AES encryption

        Raises:
            ValueError: If plaintext exceeds maximum size (65535 bytes)
        """
        plaintext_bytes = plaintext.encode('utf-8')

        if len(plaintext_bytes) > self.MAX_SECRET_SIZE:
            raise ValueError(
                _("Plaintext size ({} bytes) exceeds maximum ({} bytes).").format(
                    len(plaintext_bytes), self.MAX_SECRET_SIZE
                )
            )

        # Calculate required padding
        total_size = len(plaintext_bytes) + 2  # +2 for length header

        if total_size <= self.MIN_PADDED_SIZE:
            # Pad to minimum size
            pad_length = self.MIN_PADDED_SIZE - total_size
        else:
            # Pad to AES block boundary
            pad_length = (self.AES_BLOCK_SIZE - (total_size % self.AES_BLOCK_SIZE)) % self.AES_BLOCK_SIZE

        # Create length header (big-endian 16-bit unsigned integer)
        length = len(plaintext_bytes)
        header = bytes([length >> 8, length & 0xFF])

        # Combine header, plaintext, and random padding
        return header + plaintext_bytes + secrets_module.token_bytes(pad_length)

    def _unpad(self, padded: bytes) -> str:
        """
        Extract plaintext from padded bytes using length header.

        Reads the 2-byte big-endian length header and extracts exactly that
        many bytes as the plaintext, discarding the random padding.

        Args:
            padded: Padded bytes from decryption

        Returns:
            Original plaintext string (UTF-8 decoded)
        """
        # Read 2-byte big-endian length header
        plaintext_length = (padded[0] << 8) | padded[1]

        # Extract plaintext (skip 2-byte header, read plaintext_length bytes)
        return padded[2 : plaintext_length + 2].decode('utf-8')

    def encrypt(self, secret_key: bytes) -> None:
        """
        Encrypt plaintext using AES-256-CFB mode with random IV.

        Process:
        1. Generate random 16-byte initialization vector (IV)
        2. Pad plaintext with length header and random bytes
        3. Encrypt padded plaintext using AES-256-CFB
        4. Prepend IV to ciphertext for use in decryption
        5. Generate SHA-256 hash of plaintext for validation
        6. Clear plaintext from memory

        The ciphertext format is:
        [16-byte IV][encrypted padded data]

        Args:
            secret_key: 256-bit AES encryption key

        Raises:
            ValueError: If plaintext is not set or exceeds maximum size
        """
        if self.plaintext is None:
            raise ValueError(_("Plaintext must be set before encryption."))

        # Generate random initialization vector
        iv = secrets_module.token_bytes(self.IV_SIZE)

        # Encrypt padded plaintext
        cipher = AES.new(secret_key, AES.MODE_CFB, iv)
        padded_plaintext = self._pad(self.plaintext)
        self.ciphertext = iv + cipher.encrypt(padded_plaintext)

        # Generate validation hash using custom hasher
        self.hash = make_password(self.plaintext, hasher=SecretValidationHasher())

        # Clear plaintext from memory for security
        self.plaintext = None

    def decrypt(self, secret_key: bytes) -> None:
        """
        Decrypt ciphertext and validate against stored hash.

        Process:
        1. Extract 16-byte IV from beginning of ciphertext
        2. Decrypt remaining ciphertext using AES-256-CFB
        3. Remove padding to reveal plaintext
        4. Validate decrypted plaintext against stored hash
        5. Store plaintext in transient attribute

        Args:
            secret_key: 256-bit AES decryption key

        Raises:
            ValueError: If ciphertext is not set, decryption fails, or validation fails
        """
        if self.plaintext is not None:
            return  # Already decrypted

        if not self.ciphertext:
            raise ValueError(_("Ciphertext must be set before decryption."))

        # Extract IV and encrypted data
        iv = bytes(self.ciphertext[: self.IV_SIZE])
        encrypted_data = bytes(self.ciphertext[self.IV_SIZE :])

        # Decrypt and remove padding
        cipher = AES.new(secret_key, AES.MODE_CFB, iv)
        plaintext = self._unpad(cipher.decrypt(encrypted_data))

        # Validate decrypted plaintext against hash
        if not self.validate(plaintext):
            raise ValueError(_("Decryption failed: invalid key or corrupted ciphertext"))

        self.plaintext = plaintext

    def validate(self, plaintext: str) -> bool:
        """
        Verify plaintext matches the stored SHA-256 hash.

        This ensures the decrypted plaintext is correct and hasn't been
        corrupted or tampered with.

        Args:
            plaintext: Plaintext to validate

        Returns:
            True if plaintext matches stored hash, False otherwise

        Raises:
            ValueError: If hash has not been generated for this secret
        """
        if not self.hash:
            raise ValueError(_("Cannot validate: hash not generated for this secret."))

        return check_password(plaintext, self.hash, preferred=SecretValidationHasher())
