from django.db import migrations


def populate_secrets(apps, schema_editor):
    """Populate the Secret model with data from the SecretStore model."""
    try:
        SecretOld = apps.get_model('netbox_secretstore', 'Secret')
    except LookupError:
        # Skip if the old model doesn't exist
        return
    Secret = apps.get_model('netbox_secrets', 'Secret')

    # Retrieve the necessary data from SecretStore objects
    secrets = SecretOld.objects.values(
        'created',
        'last_updated',
        'custom_field_data',
        'id',
        'assigned_object_id',
        'name',
        'ciphertext',
        'hash',
        'assigned_object_type_id',
        'role_id',
    )

    # Queue Secrets to be created
    secrets_to_create = []
    secret_count = secrets.count()
    for i, secret in enumerate(secrets, start=1):
        secrets_to_create.append(
            Secret(
                created=secret['created'],
                last_updated=secret['last_updated'],
                custom_field_data=secret['custom_field_data'],
                id=secret['id'],
                assigned_object_id=secret['assigned_object_id'],
                name=secret['name'],
                ciphertext=secret['ciphertext'],
                assigned_object_type_id=secret['assigned_object_type_id'],
                role_id=secret['role_id'],
                hash=secret['hash'],
            ),
        )

    # Bulk create the secret objects
    Secret.objects.bulk_create(secrets_to_create, batch_size=100)


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_secrets', '0003_populate_secretroles'),
    ]

    operations = [migrations.RunPython(code=populate_secrets, reverse_code=migrations.RunPython.noop)]
