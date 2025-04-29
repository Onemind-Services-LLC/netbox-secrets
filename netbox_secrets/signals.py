from django.db.backends.signals import connection_created
from django.db.backends.postgresql.base import DatabaseWrapper
from django.dispatch import receiver


@receiver(connection_created, sender=DatabaseWrapper)
def configure_generic_relations(sender, **kwargs):
    from django.contrib.contenttypes.fields import GenericRelation
    from django.contrib.contenttypes.models import ContentType

    from .constants import SECRET_ASSIGNABLE_MODELS

    for content_type in ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS):
        GenericRelation(
            to='netbox_secrets.Secret',
            content_type_field='assigned_object_type',
            object_id_field='assigned_object_id',
            related_query_name=str(content_type.model),
        ).contribute_to_class(
            content_type.model_class(),
            'secrets',
        )
