import base64

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from netbox_secrets.models import *
from users.api.serializers import UserSerializer

__all__ = [
    'ActivateUserKeySerializer',
    'SessionKeyCreateSerializer',
    'SessionKeySerializer',
    'UserKeySerializer',
]


class UserKeySerializer(NetBoxModelSerializer):
    """
    Serializer for UserKey model.

    Handles serialization of user encryption keys, including public/private key pairs.
    The private key is write-only and never returned in responses.
    """

    user = UserSerializer(nested=True, required=False)
    public_key = serializers.CharField(help_text="RSA public key in PEM format")
    private_key = serializers.CharField(
        write_only=True, required=False, help_text="RSA private key in PEM format (write-only, used for activation)"
    )
    is_active = serializers.BooleanField(
        read_only=True, help_text="Whether this key has been activated with the master key"
    )
    is_filled = serializers.BooleanField(read_only=True, help_text="Whether this key has a public key configured")

    class Meta:
        model = UserKey
        fields = [
            'id',
            'url',
            'display_url',
            'display',
            'user',
            'public_key',
            'private_key',
            'is_active',
            'is_filled',
            'created',
            'last_updated',
            'tags',
            'custom_fields',
        ]
        brief_fields = ('id', 'display', 'url')

    def create(self, validated_data):
        # Ignore private_key (used only for activation workflows)
        validated_data.pop('private_key', None)

        request = self.context.get('request')
        if request and request.user and request.user.is_authenticated:
            validated_data.setdefault('user', request.user)

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Ignore private_key (used only for activation workflows)
        validated_data.pop('private_key', None)
        validated_data.pop('user', None)
        return super().update(instance, validated_data)


class SessionKeySerializer(serializers.ModelSerializer):
    """
    Serializer for SessionKey model.

    Represents temporary session keys used for encrypting/decrypting secrets.
    The actual session key value is only included in responses when explicitly
    provided via context (e.g., after creation).
    """

    userkey = UserKeySerializer(nested=True, read_only=True)
    session_key = serializers.SerializerMethodField(
        read_only=True, help_text="Base64-encoded session key (only returned on creation)"
    )

    class Meta:
        model = SessionKey
        fields = [
            'id',
            'userkey',
            'session_key',
            'created',
        ]
        brief_fields = ('id', 'display', 'url')

    @extend_schema_field(OpenApiTypes.STR)
    def get_session_key(self, obj):
        """Return session key from context if available (e.g., after creation)."""
        context_key = self.context.get('session_key')
        if context_key:
            return context_key
        key = getattr(obj, 'key', None)
        if key:
            return base64.b64encode(key).decode('utf-8')
        return None


class SessionKeyCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating session keys.

    Requires the user's private key to derive the session key.
    Optionally preserves existing session key instead of creating a new one.
    """

    private_key = serializers.CharField(
        write_only=True, required=True, help_text="User's RSA private key in PEM format"
    )
    preserve_key = serializers.BooleanField(
        default=False,
        write_only=True,
        required=False,
        help_text="If true, preserve existing session key instead of creating new one",
    )

    class Meta:
        model = SessionKey
        fields = ['private_key', 'preserve_key']


class ActivateUserKeySerializer(serializers.Serializer):
    """Serializer for activating user keys."""

    private_key = serializers.CharField(
        required=True,
        write_only=True,
        help_text="Administrator's RSA private key in PEM format for deriving master key",
        min_length=1,
        trim_whitespace=True,
    )
    user_key_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=True,
        help_text="List of UserKey IDs to activate",
        min_length=1,
        max_length=100,
    )

    def validate_user_key_ids(self, value):
        """Remove duplicates while preserving order."""
        return list(dict.fromkeys(value))
