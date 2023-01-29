from django.db import migrations


def populate_userkeys(apps, schema_editor):
    """Populate the UserKey model with data from the SecretStore model."""
    try:
        UserKeyOld = apps.get_model('netbox_secretstore', 'UserKey')
    except LookupError:
        # Skip if the old model doesn't exist
        return
    UserKey = apps.get_model('netbox_secrets', 'UserKey')

    # Retrieve the necessary data from SecretStore objects
    userkeys = UserKeyOld.objects.values('id', 'created', 'last_updated', 'user', 'public_key', 'master_key_cipher')

    # Queue UserKeys to be created
    userkeys_to_create = []
    userkey_count = userkeys.count()
    for i, userkey in enumerate(userkeys, start=1):
        userkeys_to_create.append(
            UserKey(
                id=userkey['id'],
                created=userkey['created'],
                last_updated=userkey['last_updated'],
                user_id=userkey['user'],
                public_key=userkey['public_key'],
                master_key_cipher=userkey['master_key_cipher'],
            ),
        )

    # Bulk create the userkey objects
    UserKey.objects.bulk_create(userkeys_to_create, batch_size=100)


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_secrets', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(code=populate_userkeys, reverse_code=migrations.RunPython.noop),
    ]
