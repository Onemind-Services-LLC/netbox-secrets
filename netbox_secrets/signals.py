import sys

from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.fields import GenericRelation
from django.db import ProgrammingError
from django.db.backends.postgresql.base import DatabaseWrapper
from django.db.backends.signals import connection_created
from django.dispatch import receiver


@receiver(connection_created, sender=DatabaseWrapper)
def configure_generic_relations(sender, **kwargs):
    if 'test' in sys.argv:
        # Skip this signal during tests to avoid issues with test database destruction
        return

    plugin_settings = settings.PLUGINS_CONFIG.get("netbox_secrets", {})
    model_list = plugin_settings.get("apps", [])

    try:
        for model_path in model_list:
            try:
                app_label, model_name = model_path.split(".", 1)
            except (LookupError, ValueError):
                continue

            model_class = apps.get_model(app_label, model_name)

            if model_class is None:
                continue

            if not hasattr(model_class, "secrets"):
                GenericRelation(
                    to="netbox_secrets.Secret",
                    content_type_field="assigned_object_type",
                    object_id_field="assigned_object_id",
                    related_query_name=model_name,
                ).contribute_to_class(model_class, "secrets")

    except ProgrammingError:
        # DB may still not be ready during very early migrations
        pass
