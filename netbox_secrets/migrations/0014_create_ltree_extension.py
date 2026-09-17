from django.contrib.postgres.operations import CreateExtension
from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0013_alter_secretrole_options_and_more'),
    ]

    operations = [
        CreateExtension('ltree'),
    ]