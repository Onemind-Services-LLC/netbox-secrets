# Generated manually for X25519 key type and TOTP support

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0009_add_owner_field'),
    ]

    operations = [
        # Add key_type field to UserKey for X25519 support
        migrations.AddField(
            model_name='userkey',
            name='key_type',
            field=models.CharField(
                max_length=10,
                choices=[('rsa', 'RSA'), ('x25519', 'X25519')],
                default='rsa',
                verbose_name='Key type',
                help_text='Type of cryptographic key (RSA or X25519)',
            ),
        ),

        # Add TOTP fields to Secret model
        migrations.AddField(
            model_name='secret',
            name='totp_ciphertext',
            field=models.BinaryField(
                max_length=256,
                editable=False,
                blank=True,
                null=True,
                help_text='Encrypted TOTP seed (base32-encoded secret)',
            ),
        ),
        migrations.AddField(
            model_name='secret',
            name='totp_hash',
            field=models.CharField(
                max_length=128,
                editable=False,
                blank=True,
                null=True,
                help_text='SHA256 hash of TOTP seed for validation',
            ),
        ),
        migrations.AddField(
            model_name='secret',
            name='totp_issuer',
            field=models.CharField(
                max_length=100,
                blank=True,
                default='',
                help_text='TOTP issuer name (e.g., service name)',
            ),
        ),
        migrations.AddField(
            model_name='secret',
            name='totp_digits',
            field=models.PositiveSmallIntegerField(
                default=6,
                help_text='Number of digits in TOTP code (default: 6)',
            ),
        ),
        migrations.AddField(
            model_name='secret',
            name='totp_period',
            field=models.PositiveSmallIntegerField(
                default=30,
                help_text='TOTP validity period in seconds (default: 30)',
            ),
        ),
    ]
