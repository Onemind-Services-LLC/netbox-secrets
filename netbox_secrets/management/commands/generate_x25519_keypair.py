"""
Django management command to generate an X25519 keypair.

Usage:
    python manage.py generate_x25519_keypair [name]
    python manage.py generate_x25519_keypair provisioning-service --output-dir ./secrets

This generates a keypair suitable for use with netbox-secrets.
"""
import os

from django.core.management.base import BaseCommand, CommandError

from netbox_secrets.utils import generate_x25519_keypair, NACL_AVAILABLE


class Command(BaseCommand):
    help = 'Generate an X25519 keypair for use with netbox-secrets'

    def add_arguments(self, parser):
        parser.add_argument(
            'name',
            type=str,
            nargs='?',
            default='service',
            help='Name for the keypair files (default: service)',
        )
        parser.add_argument(
            '--output-dir',
            type=str,
            default='.',
            help='Directory to write the keypair files (default: current directory)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Overwrite existing files',
        )

    def handle(self, *args, **options):
        if not NACL_AVAILABLE:
            raise CommandError(
                "pynacl is required for X25519 support. Install with: pip install pynacl"
            )

        name = options['name']
        output_dir = options['output_dir']
        force = options['force']

        # Ensure output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        private_key_path = os.path.join(output_dir, f'{name}.key')
        public_key_path = os.path.join(output_dir, f'{name}.pub')

        # Check for existing files
        if not force:
            if os.path.exists(private_key_path):
                raise CommandError(
                    f"Private key file already exists: {private_key_path}. Use --force to overwrite."
                )
            if os.path.exists(public_key_path):
                raise CommandError(
                    f"Public key file already exists: {public_key_path}. Use --force to overwrite."
                )

        # Generate the keypair
        private_key_pem, public_key_pem = generate_x25519_keypair()

        # Write private key
        with open(private_key_path, 'w') as f:
            f.write(private_key_pem)
        os.chmod(private_key_path, 0o600)

        # Write public key
        with open(public_key_path, 'w') as f:
            f.write(public_key_pem)
        os.chmod(public_key_path, 0o644)

        self.stdout.write(self.style.SUCCESS(f'Generated X25519 keypair:'))
        self.stdout.write(f'  Private key: {private_key_path} (mode: 600)')
        self.stdout.write(f'  Public key:  {public_key_path} (mode: 644)')
        self.stdout.write('')
        self.stdout.write('To use this key with NetBox Secrets:')
        self.stdout.write(f'  1. Create a UserKey in NetBox with the contents of {public_key_path}')
        self.stdout.write(f'  2. Store {private_key_path} securely (never commit to version control)')
        self.stdout.write(f'  3. Use the private key to decrypt secrets via the API')
        self.stdout.write('')
        self.stdout.write(self.style.WARNING(
            'IMPORTANT: Keep the private key secure and never share it!'
        ))
