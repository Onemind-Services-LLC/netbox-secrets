from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from core.models import ObjectType
from netbox.api.fields import ContentTypeField
from netbox.api.gfk_fields import GFKSerializerField
from netbox.api.serializers import NestedGroupModelSerializer, PrimaryModelSerializer
from netbox_secrets.constants import SECRET_ASSIGNABLE_MODELS
from netbox_secrets.models import *
from utilities.api import get_serializer_for_model
from .nested import NestedSecretRoleSerializer

__all__ = [
    'SecretRoleSerializer',
    'SecretSerializer',
]


class SecretRoleSerializer(NestedGroupModelSerializer):
    parent = NestedSecretRoleSerializer(required=False, allow_null=True)
    secret_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = SecretRole
        fields = [
            'id',
            'url',
            'display_url',
            'display',
            'name',
            'slug',
            'parent',
            'description',
            'tags',
            'custom_fields',
            'created',
            'last_updated',
            'secret_count',
            'owner',
            'comments',
            '_depth',
        ]
        brief_fields = ('id', 'url', 'display', 'name', 'slug', 'description', 'secret_count', '_depth')


class SecretSerializer(PrimaryModelSerializer):
    role = SecretRoleSerializer(nested=True, required=False)
    assigned_object_type = ContentTypeField(queryset=ObjectType.objects.filter(SECRET_ASSIGNABLE_MODELS))
    assigned_object = GFKSerializerField(read_only=True)
    plaintext = serializers.CharField(required=False, help_text="Plaintext secret value (encrypted at rest)")
    hash = serializers.CharField(read_only=True, help_text="SHA-256 hash for validation (read-only)")

    class Meta:
        model = Secret
        fields = [
            'id',
            'url',
            'display',
            'assigned_object_type',
            'assigned_object_id',
            'assigned_object',
            'role',
            'name',
            'plaintext',
            'hash',
            'description',
            'comments',
            'tags',
            'custom_fields',
            'created',
            'last_updated',
        ]
        validators = []
        brief_fields = ('id', 'display', 'name', 'url')

    @extend_schema_field(serializers.JSONField(allow_null=True))
    def get_assigned_object(self, obj):
        """
        Serialize the assigned object using its model-specific serializer.

        Returns:
            Nested serialized representation of the assigned object, or None
        """
        if obj.assigned_object is None:
            return None

        serializer = get_serializer_for_model(obj.assigned_object)
        context = {'request': self.context.get('request')}
        return serializer(obj.assigned_object, nested=True, context=context).data

    def validate(self, data):
        """
        Validate and encrypt plaintext data.

        If plaintext is provided and a master key is available in context,
        encrypts the plaintext and stores the ciphertext and hash.

        Args:
            data: Validated data dictionary

        Returns:
            Validated data with ciphertext and hash added

        Raises:
            ValidationError: If plaintext provided but no master key in context
        """
        plaintext = data.get('plaintext')

        if plaintext:
            master_key = self.context.get('master_key')

            if master_key is None:
                raise serializers.ValidationError(
                    {'plaintext': 'Cannot encrypt secret: master key not available in context'}
                )

            # Create temporary Secret instance for encryption
            secret = Secret(plaintext=plaintext)
            secret.encrypt(master_key)

            # Store encrypted data
            data['ciphertext'] = secret.ciphertext
            data['hash'] = secret.hash

            # Remove plaintext from data as it's now encrypted
            data.pop('plaintext', None)

        return super().validate(data)
