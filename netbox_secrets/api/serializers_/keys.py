from functools import cached_property

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework.utils.serializer_helpers import BindingDict

from netbox.api.serializers import NetBoxModelSerializer
from netbox_secrets.models import *
from users.api.serializers import UserSerializer
from utilities.api import get_related_object_by_attrs

__all__ = [
    'ActivateUserKeySerializer',
    'RSAKeyPairSerializer',
    'SessionKeyCreateSerializer',
    'SessionKeySerializer',
    'UserKeySerializer',
]


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


class RSAKeyPairSerializer(serializers.Serializer):
    """
    Serializer for RSA key pair generation responses.

    Used by the generate-rsa-key-pair endpoint to return newly generated keys.
    """

    public_key = serializers.CharField(help_text="RSA public key in PEM format")
    private_key = serializers.CharField(help_text="RSA private key in PEM format (keep secure!)")


class ActivateUserKeySerializer(serializers.Serializer):
    """
    Serializer for activating user keys.

    Used by administrators to activate multiple user keys using a master key
    derived from their own private key.
    """

    private_key = serializers.CharField(
        write_only=True, required=True, help_text="Administrator's RSA private key for deriving master key"
    )
    user_keys = serializers.ListField(
        child=serializers.IntegerField(), required=True, help_text="List of UserKey IDs to activate"
    )


class UserKeySerializer(NetBoxModelSerializer):
    """
    Serializer for UserKey model.

    Handles serialization of user encryption keys, including public/private key pairs.
    The private key is write-only and never returned in responses.
    """

    user = UserSerializer(nested=True, read_only=True)
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


class SessionKeySerializer(serializers.ModelSerializer):
    """
    Serializer for SessionKey model.

    Represents temporary session keys used for encrypting/decrypting secrets.
    The actual session key value is only included in responses when explicitly
    provided via context (e.g., after creation).
    """

    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:sessionkey-detail')
    userkey = UserKeySerializer(nested=True, read_only=True)
    session_key = serializers.SerializerMethodField(
        read_only=True, help_text="Base64-encoded session key (only returned on creation)"
    )
    display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = SessionKey
        fields = [
            'id',
            'url',
            'display',
            'userkey',
            'session_key',
            'created',
        ]
        brief_fields = ('id', 'display', 'url')

    def __init__(self, *args, nested=False, fields=None, **kwargs):
        """
        Initialize serializer with support for nested representation.

        Args:
            nested: Whether this is a nested serializer
            fields: Specific fields to include (for field filtering)
        """
        self.nested = nested
        self._requested_fields = fields

        if self.nested:
            self.validators = []
            if not fields:
                self._requested_fields = getattr(self.Meta, 'brief_fields', None)

        super().__init__(*args, **kwargs)

    @cached_property
    def fields(self):
        """
        Override fields property to support field filtering.

        Returns only the requested fields if specified, otherwise all fields.
        """
        if not self._requested_fields:
            return super().fields

        fields = BindingDict(self)
        for key, value in self.get_fields().items():
            if key in self._requested_fields:
                fields[key] = value
        return fields

    def to_internal_value(self, data):
        """
        Convert incoming data to internal representation.

        For nested serializers, expects attributes or PK identifying the related object.
        """
        if self.nested:
            queryset = self.Meta.model.objects.all()
            return get_related_object_by_attrs(queryset, data)

        return super().to_internal_value(data)

    @extend_schema_field(OpenApiTypes.STR)
    def get_display(self, obj):
        return str(obj)

    @extend_schema_field(OpenApiTypes.STR)
    def get_session_key(self, obj):
        """Return session key from context if available (e.g., after creation)."""
        return self.context.get('session_key', None)
