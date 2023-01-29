from django.db import migrations


def populate_secretroles(apps, schema_editor):
    """Populate the SecretRole model with data from the SecretStore model."""
    try:
        SecretRoleOld = apps.get_model('netbox_secretstore', 'SecretRole')
    except LookupError:
        # Skip if the old model doesn't exist
        return
    SecretRole = apps.get_model('netbox_secrets', 'SecretRole')

    # Retrieve the necessary data from SecretStore objects
    roles = SecretRoleOld.objects.values(
        'id',
        'name',
        'slug',
        'description',
        'created',
        'last_updated',
        'custom_field_data',
    )

    # Queue SecretRoles to be created
    roles_to_create = []
    role_count = roles.count()
    for i, role in enumerate(roles, start=1):
        roles_to_create.append(
            SecretRole(
                id=role['id'],
                name=role['name'],
                slug=role['slug'],
                description=role['description'],
                created=role['created'],
                last_updated=role['last_updated'],
                custom_field_data=role['custom_field_data'],
            ),
        )

    # Bulk create the role objects
    SecretRole.objects.bulk_create(roles_to_create, batch_size=100)


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_secrets', '0002_populate_userkeys'),
    ]

    operations = [
        migrations.RunPython(code=populate_secretroles, reverse_code=migrations.RunPython.noop),
    ]
