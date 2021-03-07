from django.db import migrations


class Migration(migrations.Migration):

    replaces = [
        ('secrets', '0009_secretrole_drop_users_groups')
    ]
    dependencies = [
        ('netbox_secretstore', '0008_standardize_description'),
        ('users', '0009_replicate_permissions'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='secretrole',
            name='groups',
        ),
        migrations.RemoveField(
            model_name='secretrole',
            name='users',
        ),
    ]
