import logging
import sys

from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.fields import GenericRelation
from django.db import ProgrammingError
from django.db.backends.postgresql.base import DatabaseWrapper
from django.db.backends.signals import connection_created
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(connection_created, sender=DatabaseWrapper)
def configure_generic_relations(sender, **kwargs):
    """Dynamically attach a `secrets` GenericRelation to models listed in PLUGINS_CONFIG."""
    if "test" in sys.argv:
        return

    model_list = settings.PLUGINS_CONFIG.get("netbox_secrets", {}).get("apps", [])
    if not model_list:
        return

    for model_path in model_list:
        try:
            app_label, model_name = model_path.split(".", 1)
        except ValueError:
            logger.warning("netbox_secrets: invalid model path %r, expected 'app_label.ModelName'", model_path)
            continue

        try:
            model_class = apps.get_model(app_label, model_name)
        except (LookupError, ProgrammingError):
            logger.warning("netbox_secrets: could not load model %r — skipping", model_path)
            continue

        if hasattr(model_class, "secrets"):
            continue

        GenericRelation(
            to="netbox_secrets.Secret",
            content_type_field="assigned_object_type",
            object_id_field="assigned_object_id",
            related_query_name=model_name,
        ).contribute_to_class(model_class, "secrets")
        logger.debug("netbox_secrets: attached `secrets` relation to %s", model_path)
