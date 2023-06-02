# Generated by Django 4.1.9 on 2023-05-07 18:36

from django.contrib.contenttypes.models import ContentType
from django.db import migrations, models


def copy_assigned_object(apps, schema_editor):
    Secret = apps.get_model('netbox_secrets', 'Secret')

    for secret in Secret.objects.all():
        content_type = ContentType.objects.get(id=secret.assigned_object_type_id)
        Model = apps.get_model(content_type.app_label, str(content_type.model).capitalize())
        object = Model.objects.filter(id=secret.assigned_object_id).first()
        secret._object_repr = object.name
        secret.save()


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_secrets', '0006_alter_userkey_created_alter_userkey_last_updated'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='_object_repr',
            field=models.CharField(blank=True, editable=False, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='secret',
            name='comments',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='secret',
            name='description',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AddField(
            model_name='secretrole',
            name='comments',
            field=models.TextField(blank=True),
        ),
        migrations.RunPython(copy_assigned_object)
    ]
