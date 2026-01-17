"""
Migration for zero-knowledge secret sharing models.

Creates:
- TenantMembership: Links users to tenants with encrypted tenant keys
- TenantServiceAccount: Service accounts with activation-based access
- TenantSecret: Client-side encrypted secrets
"""
import secrets

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('tenancy', '0001_initial'),
        ('contenttypes', '0002_remove_content_type_name'),
        ('netbox_secrets', '0010_x25519_and_totp_support'),
    ]

    operations = [
        # TenantMembership: Links users to tenants with their encrypted tenant key
        migrations.CreateModel(
            name='TenantMembership',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=None)),
                ('public_key', models.TextField(help_text='X25519 public key in PEM format')),
                ('webauthn_credential_id', models.CharField(help_text='WebAuthn credential ID (base64url encoded)', max_length=512)),
                ('encrypted_private_key', models.BinaryField(help_text="X25519 private key encrypted with WebAuthn PRF-derived key", max_length=256)),
                ('encrypted_tenant_key', models.BinaryField(help_text="Tenant key encrypted with member's X25519 public key (SealedBox)", max_length=256)),
                ('role', models.CharField(choices=[('member', 'Member'), ('admin', 'Admin')], default='member', max_length=20)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='crypto_memberships', to='tenancy.tenant')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tenant_crypto_memberships', to=settings.AUTH_USER_MODEL)),
                ('added_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='added_tenant_memberships', to=settings.AUTH_USER_MODEL)),
                ('tags', models.ManyToManyField(blank=True, related_name='+', to='extras.tag')),
            ],
            options={
                'verbose_name': 'Tenant Crypto Membership',
                'verbose_name_plural': 'Tenant Crypto Memberships',
                'ordering': ['tenant', 'user'],
                'unique_together': {('tenant', 'user')},
            },
        ),
        # TenantServiceAccount: Service accounts for automation
        migrations.CreateModel(
            name='TenantServiceAccount',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=None)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True)),
                ('public_key', models.TextField(help_text='X25519 public key in PEM format')),
                ('encrypted_private_key', models.BinaryField(help_text='X25519 private key encrypted with activation key (AES-256-GCM)', max_length=256)),
                ('encrypted_tenant_key', models.BinaryField(help_text="Tenant key encrypted with service account's X25519 public key", max_length=256)),
                ('activation_salt', models.BinaryField(help_text='Salt for activation key derivation', max_length=32)),
                ('private_key_nonce', models.BinaryField(help_text='AES-GCM nonce for private key encryption', max_length=12)),
                ('token', models.CharField(help_text='API token for service account authentication', max_length=64, unique=True)),
                ('token_last_used', models.DateTimeField(blank=True, null=True)),
                ('enabled', models.BooleanField(default=True)),
                ('last_activated', models.DateTimeField(blank=True, null=True)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='crypto_service_accounts', to='tenancy.tenant')),
                ('last_activated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='activated_tenant_service_accounts', to=settings.AUTH_USER_MODEL)),
                ('tags', models.ManyToManyField(blank=True, related_name='+', to='extras.tag')),
            ],
            options={
                'verbose_name': 'Tenant Service Account',
                'verbose_name_plural': 'Tenant Service Accounts',
                'ordering': ['tenant', 'name'],
                'unique_together': {('tenant', 'name')},
            },
        ),
        # TenantSecret: Client-side encrypted secrets
        migrations.CreateModel(
            name='TenantSecret',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=None)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, help_text='Description (stored in plaintext - do not include sensitive data)')),
                ('ciphertext', models.BinaryField(help_text='AES-256-GCM encrypted secret data', max_length=65600)),
                ('totp_ciphertext', models.BinaryField(blank=True, help_text='Encrypted TOTP seed (same encryption as main secret)', max_length=256, null=True)),
                ('totp_issuer', models.CharField(blank=True, max_length=100)),
                ('totp_digits', models.PositiveSmallIntegerField(default=6)),
                ('totp_period', models.PositiveSmallIntegerField(default=30)),
                ('assigned_object_id', models.PositiveIntegerField(blank=True, null=True)),
                ('metadata', models.JSONField(blank=True, help_text='Optional metadata (NOT encrypted - do not include sensitive data)', null=True)),
                ('last_accessed', models.DateTimeField(blank=True, help_text='Last time this secret was decrypted', null=True)),
                ('access_count', models.PositiveIntegerField(default=0, help_text='Number of times this secret has been accessed')),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='crypto_secrets', to='tenancy.tenant')),
                ('assigned_object_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='tenant_secrets', to='contenttypes.contenttype')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_tenant_secrets', to=settings.AUTH_USER_MODEL)),
                ('last_modified_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='modified_tenant_secrets', to=settings.AUTH_USER_MODEL)),
                ('tags', models.ManyToManyField(blank=True, related_name='+', to='extras.tag')),
            ],
            options={
                'verbose_name': 'Tenant Secret',
                'verbose_name_plural': 'Tenant Secrets',
                'ordering': ['tenant', 'name'],
                'unique_together': {('tenant', 'name')},
            },
        ),
    ]
