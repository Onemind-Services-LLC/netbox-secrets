import sys
from django.conf import settings
from django.contrib.contenttypes.fields import GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import ProgrammingError
from django.db.backends.postgresql.base import DatabaseWrapper
from django.db.backends.signals import connection_created
from django.dispatch import receiver


@receiver(connection_created, sender=DatabaseWrapper)
def configure_generic_relations(sender, **kwargs):
    if 'test' in sys.argv:
        # Skip this signal during tests to avoid issues with test database destruction
        return

    from .constants import SECRET_ASSIGNABLE_MODELS
    from .models import Secret

    plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets', {})

    try:
        for content_type in ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS):
            model_class = content_type.model_class()
            if model_class is None:
                continue
            if not hasattr(model_class, 'secrets'):
                GenericRelation(
                    to='netbox_secrets.Secret',
                    content_type_field='assigned_object_type',
                    object_id_field='assigned_object_id',
                    related_query_name=str(content_type.model),
                ).contribute_to_class(
                    model_class,
                    'secrets',
                )

        if plugin_settings.get('enable_contacts', False):
            if not hasattr(Secret, 'contacts'):
                GenericRelation(
                    to='tenancy.ContactAssignment',
                    content_type_field='object_type',
                    object_id_field='object_id',
                    related_query_name='secret',
                ).contribute_to_class(Secret, 'contacts')

    except ProgrammingError:
        # DB may still not be ready during very early migrations
        pass
