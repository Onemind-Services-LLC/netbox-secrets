from functools import cached_property

from django.contrib.contenttypes.models import ContentType
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from rest_framework.utils.serializer_helpers import BindingDict

from netbox.api.fields import ContentTypeField
from netbox.api.serializers import NetBoxModelSerializer
from users.api.serializers import UserSerializer
from utilities.api import get_related_object_by_attrs, get_serializer_for_model
from ..constants import SECRET_ASSIGNABLE_MODELS
from ..models import *

__all__ = [
    'SecretRoleSerializer',
    'SecretSerializer',
    'SessionKeySerializer',
    'SessionKeyCreateSerializer',
    'UserKeySerializer',
    'RSAKeyPairSerializer',
    # Zero-knowledge group models
    'TenantMembershipSerializer',
    'TenantMembershipCreateSerializer',
    'TenantServiceAccountSerializer',
    'TenantServiceAccountCreateSerializer',
    'TenantServiceAccountActivateSerializer',
    'TenantSecretSerializer',
    'TenantSecretCreateSerializer',
]


#
# User Key
#


class UserKeySerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:userkey-detail')
    user = UserSerializer(
        nested=True,
    )
    public_key = serializers.CharField()
    private_key = serializers.CharField(
        write_only=True,
    )

    display = serializers.SerializerMethodField(read_only=True)

    is_active = serializers.BooleanField(read_only=True)

    is_filled = serializers.BooleanField(read_only=True)

    class Meta:
        model = UserKey
        fields = [
            'pk',
            'id',
            'url',
            'display',
            'user',
            'public_key',
            'private_key',
            'created',
            'last_updated',
            'is_active',
            'is_filled',
        ]
        brief_fields = ('id', 'display', 'url')


#
# Session Keys
#


class SessionKeySerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:sessionkey-detail')

    display = serializers.SerializerMethodField(read_only=True)

    userkey = UserKeySerializer(nested=True)

    session_key = serializers.SerializerMethodField(
        read_only=True,
    )

    class Meta:
        model = SessionKey
        fields = [
            'pk',
            'id',
            'url',
            'display',
            'userkey',
            'session_key',
            'created',
        ]
        brief_fields = ('id', 'display', 'url')

    @extend_schema_field(OpenApiTypes.STR)
    def get_display(self, obj):
        return str(obj)

    @extend_schema_field(OpenApiTypes.STR)
    def get_session_key(self, obj):
        return self.context.get('session_key', None)

    def __init__(self, *args, nested=False, fields=None, **kwargs):
        self.nested = nested
        self._requested_fields = fields
        if self.nested:
            self.validators = []
        if self.nested and not fields:
            self._requested_fields = getattr(self.Meta, 'brief_fields', None)
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        # If initialized as a nested serializer, we should expect to receive the attrs or PK
        # identifying a related object.
        if self.nested:
            queryset = self.Meta.model.objects.all()
            return get_related_object_by_attrs(queryset, data)

        return super().to_internal_value(data)

    @cached_property
    def fields(self):
        """
        Override the fields property to check for requested fields. If defined,
        return only the applicable fields.
        """
        if not self._requested_fields:
            return super().fields

        fields = BindingDict(self)
        for key, value in self.get_fields().items():
            if key in self._requested_fields:
                fields[key] = value
        return fields


class SessionKeyCreateSerializer(serializers.ModelSerializer):
    private_key = serializers.CharField(
        write_only=True,
    )

    preserve_key = serializers.BooleanField(
        default=False,
        write_only=True,
    )

    class Meta:
        model = SessionKey
        fields = [
            'preserve_key',
            'private_key',
        ]


#
# Secret Roles
#


class SecretRoleSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secretrole-detail')
    secret_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = SecretRole
        fields = [
            'id',
            'url',
            'display',
            'name',
            'slug',
            'description',
            'comments',
            'custom_fields',
            'created',
            'last_updated',
            'secret_count',
        ]
        brief_fields = ('id', 'name', 'display', 'url', 'secret_count', 'slug')


#
# Secrets
#


class SecretSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secret-detail')
    assigned_object_type = ContentTypeField(queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS))
    assigned_object = serializers.SerializerMethodField(read_only=True)
    role = SecretRoleSerializer(nested=True)
    plaintext = serializers.CharField()

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

    @extend_schema_field(serializers.JSONField())
    def get_assigned_object(self, obj):
        if obj.assigned_object is None:
            return None
        serializer = get_serializer_for_model(obj.assigned_object)
        context = {'request': self.context['request']}
        return serializer(obj.assigned_object, nested=True, context=context).data

    def validate(self, data):
        # Encrypt plaintext data using the master key provided from the view context
        if data.get('plaintext'):
            s = Secret(plaintext=data['plaintext'])
            s.encrypt(self.context['master_key'])
            data['ciphertext'] = s.ciphertext
            data['hash'] = s.hash

        super().validate(data)

        return data


class RSAKeyPairSerializer(serializers.Serializer):
    public_key = serializers.CharField()
    private_key = serializers.CharField()


class ActivateUserKeySerializer(serializers.Serializer):
    private_key = serializers.CharField()
    user_keys = serializers.ListField()


#
# Zero-Knowledge Tenant Crypto Models
#

class TenantMembershipSerializer(NetBoxModelSerializer):
    """Serializer for TenantMembership - read operations."""
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_secrets-api:tenantmembership-detail'
    )
    user = UserSerializer(nested=True, read_only=True)
    tenant = serializers.SerializerMethodField()
    added_by = UserSerializer(nested=True, read_only=True)
    is_admin = serializers.BooleanField(read_only=True, source='is_admin')

    class Meta:
        model = TenantMembership
        fields = [
            'id',
            'url',
            'display',
            'tenant',
            'user',
            'public_key',
            'webauthn_credential_id',
            'role',
            'is_admin',
            'added_by',
            'created',
            'last_updated',
        ]
        brief_fields = ('id', 'url', 'display', 'tenant', 'user', 'role')

    @extend_schema_field(serializers.JSONField())
    def get_tenant(self, obj):
        from tenancy.api.serializers import TenantSerializer
        return TenantSerializer(obj.tenant, nested=True, context=self.context).data


class TenantMembershipCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating TenantMembership - handles encrypted data."""
    public_key = serializers.CharField()
    webauthn_credential_id = serializers.CharField()
    encrypted_private_key = serializers.CharField()  # Base64 encoded
    encrypted_tenant_key = serializers.CharField()  # Base64 encoded
    role = serializers.ChoiceField(
        choices=TenantMembership.ROLE_CHOICES,
        default=TenantMembership.ROLE_MEMBER
    )

    class Meta:
        model = TenantMembership
        fields = [
            'tenant',
            'public_key',
            'webauthn_credential_id',
            'encrypted_private_key',
            'encrypted_tenant_key',
            'role',
        ]

    def validate_encrypted_private_key(self, value):
        """Convert base64 to bytes."""
        import base64
        try:
            return base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 encoding")

    def validate_encrypted_tenant_key(self, value):
        """Convert base64 to bytes."""
        import base64
        try:
            return base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 encoding")

    def create(self, validated_data):
        # Set the user from the request
        validated_data['user'] = self.context['request'].user
        validated_data['added_by'] = self.context['request'].user
        return super().create(validated_data)


class TenantServiceAccountSerializer(NetBoxModelSerializer):
    """Serializer for TenantServiceAccount - read operations."""
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_secrets-api:tenantserviceaccount-detail'
    )
    tenant = serializers.SerializerMethodField()
    last_activated_by = UserSerializer(nested=True, read_only=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = TenantServiceAccount
        fields = [
            'id',
            'url',
            'display',
            'name',
            'description',
            'tenant',
            'public_key',
            'enabled',
            'is_active',
            'last_activated',
            'last_activated_by',
            'token_last_used',
            'created',
            'last_updated',
        ]
        brief_fields = ('id', 'url', 'display', 'name', 'tenant', 'is_active')

    @extend_schema_field(serializers.JSONField())
    def get_tenant(self, obj):
        from tenancy.api.serializers import TenantSerializer
        return TenantSerializer(obj.tenant, nested=True, context=self.context).data


class TenantServiceAccountCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating TenantServiceAccount."""
    public_key = serializers.CharField()
    encrypted_private_key = serializers.CharField()  # Base64
    encrypted_tenant_key = serializers.CharField()  # Base64
    activation_salt = serializers.CharField()  # Base64
    private_key_nonce = serializers.CharField()  # Base64

    class Meta:
        model = TenantServiceAccount
        fields = [
            'tenant',
            'name',
            'description',
            'public_key',
            'encrypted_private_key',
            'encrypted_tenant_key',
            'activation_salt',
            'private_key_nonce',
        ]

    def _decode_base64(self, value, field_name):
        import base64
        try:
            return base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError({field_name: "Invalid base64 encoding"})

    def validate_encrypted_private_key(self, value):
        return self._decode_base64(value, 'encrypted_private_key')

    def validate_encrypted_tenant_key(self, value):
        return self._decode_base64(value, 'encrypted_tenant_key')

    def validate_activation_salt(self, value):
        return self._decode_base64(value, 'activation_salt')

    def validate_private_key_nonce(self, value):
        return self._decode_base64(value, 'private_key_nonce')


class TenantServiceAccountActivateSerializer(serializers.Serializer):
    """Serializer for activating a service account."""
    service_account_id = serializers.IntegerField()
    decrypted_private_key = serializers.CharField()  # Base64 encoded

    def validate_decrypted_private_key(self, value):
        import base64
        try:
            decoded = base64.b64decode(value)
            if len(decoded) != 32:
                raise serializers.ValidationError("Private key must be 32 bytes")
            return decoded
        except Exception as e:
            raise serializers.ValidationError(f"Invalid private key: {e}")


class TenantSecretSerializer(NetBoxModelSerializer):
    """Serializer for TenantSecret - read operations (returns ciphertext, not plaintext)."""
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_secrets-api:tenantsecret-detail'
    )
    tenant = serializers.SerializerMethodField()
    created_by = UserSerializer(nested=True, read_only=True)
    last_modified_by = UserSerializer(nested=True, read_only=True)
    ciphertext = serializers.SerializerMethodField()
    totp_ciphertext = serializers.SerializerMethodField()
    has_totp = serializers.BooleanField(read_only=True)

    class Meta:
        model = TenantSecret
        fields = [
            'id',
            'url',
            'display',
            'name',
            'description',
            'tenant',
            'ciphertext',
            'has_totp',
            'totp_ciphertext',
            'totp_issuer',
            'totp_digits',
            'totp_period',
            'assigned_object_type',
            'assigned_object_id',
            'metadata',
            'created_by',
            'last_modified_by',
            'last_accessed',
            'access_count',
            'created',
            'last_updated',
        ]
        brief_fields = ('id', 'url', 'display', 'name', 'tenant')

    @extend_schema_field(serializers.JSONField())
    def get_tenant(self, obj):
        from tenancy.api.serializers import TenantSerializer
        return TenantSerializer(obj.tenant, nested=True, context=self.context).data

    @extend_schema_field(OpenApiTypes.STR)
    def get_ciphertext(self, obj):
        """Return ciphertext as base64."""
        import base64
        if obj.ciphertext:
            return base64.b64encode(bytes(obj.ciphertext)).decode()
        return None

    @extend_schema_field(OpenApiTypes.STR)
    def get_totp_ciphertext(self, obj):
        """Return TOTP ciphertext as base64."""
        import base64
        if obj.totp_ciphertext:
            return base64.b64encode(bytes(obj.totp_ciphertext)).decode()
        return None


class TenantSecretCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating TenantSecret."""
    ciphertext = serializers.CharField()  # Base64 encoded
    totp_ciphertext = serializers.CharField(required=False, allow_null=True)  # Base64

    class Meta:
        model = TenantSecret
        fields = [
            'tenant',
            'name',
            'description',
            'ciphertext',
            'totp_ciphertext',
            'totp_issuer',
            'totp_digits',
            'totp_period',
            'assigned_object_type',
            'assigned_object_id',
            'metadata',
        ]

    def validate_ciphertext(self, value):
        import base64
        try:
            return base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 encoding")

    def validate_totp_ciphertext(self, value):
        if not value:
            return None
        import base64
        try:
            return base64.b64decode(value)
        except Exception:
            raise serializers.ValidationError("Invalid base64 encoding")

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        validated_data['last_modified_by'] = self.context['request'].user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data['last_modified_by'] = self.context['request'].user
        return super().update(instance, validated_data)
