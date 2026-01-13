from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers

from netbox.api.serializers import WritableNestedSerializer
from netbox_secrets import models

__all__ = [
    'NestedSecretRoleSerializer',
]


@extend_schema_serializer(
    exclude_fields=('secret_count',),
)
class NestedSecretRoleSerializer(WritableNestedSerializer):
    secret_count = serializers.IntegerField(read_only=True)
    _depth = serializers.IntegerField(source='level', read_only=True)

    class Meta:
        model = models.SecretRole
        fields = ['id', 'url', 'display_url', 'display', 'name', 'slug', 'secret_count', '_depth']
