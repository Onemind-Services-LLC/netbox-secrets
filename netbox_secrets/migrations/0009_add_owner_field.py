# Generated manually for NetBox 4.5 compatibility
# Adds owner field from OwnerMixin (inherited via PrimaryModel)
# Uses db_constraint=False to allow applying on NetBox < 4.5 where users_owner doesn't exist.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0008_userkey_custom_field_data_userkey_tags'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                db_constraint=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.Owner',
            ),
        ),
        migrations.AddField(
            model_name='secretrole',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                db_constraint=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.Owner',
            ),
        ),
    ]
