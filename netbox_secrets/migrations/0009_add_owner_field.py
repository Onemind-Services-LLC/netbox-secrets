# Generated manually for NetBox 4.5 compatibility
# Adds owner field from OwnerMixin (inherited via PrimaryModel)

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0015_owner'),  # users.Owner model (NetBox 4.5+)
        ('netbox_secrets', '0008_userkey_custom_field_data_userkey_tags'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.owner',
            ),
        ),
        migrations.AddField(
            model_name='secretrole',
            name='owner',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='users.owner',
            ),
        ),
    ]
