from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field
from netbox.api.fields import ContentTypeField
from netbox.api.serializers import NetBoxModelSerializer
from netbox.constants import NESTED_SERIALIZER_PREFIX
from rest_framework import serializers
from utilities.api import get_serializer_for_model

from ..constants import SECRET_ASSIGNABLE_MODELS
from ..models import *
from .nested_serializers import *

__all__ = [
    'SecretRoleSerializer',
    'SecretSerializer',
    'SessionKeySerializer',
    'SessionKeyCreateSerializer',
    'UserKeySerializer',
    'RSAKeyPairSerializer',
]


#
# User Key
#


class UserKeySerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:userkey-detail')
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
            'public_key',
            'private_key',
            'created',
            'last_updated',
            'is_active',
            'is_filled',
        ]

    @extend_schema_field(serializers.CharField())
    def get_display(self, obj):
        return str(obj)


#
# Session Keys
#


class SessionKeySerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:sessionkey-detail')

    display = serializers.SerializerMethodField(read_only=True)

    userkey = NestedUserKeySerializer()

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

    @extend_schema_field(serializers.CharField())
    def get_display(self, obj):
        return str(obj)

    @extend_schema_field(serializers.CharField())
    def get_session_key(self, obj):
        return self.context.get('session_key', None)


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
            'private_key',
            'preserve_key',
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


#
# Secrets
#


class SecretSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secret-detail')
    assigned_object_type = ContentTypeField(queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS))
    assigned_object = serializers.SerializerMethodField(read_only=True)
    role = NestedSecretRoleSerializer()
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

    @extend_schema_field(serializers.DictField())
    def get_assigned_object(self, obj):
        serializer = get_serializer_for_model(obj.assigned_object, prefix=NESTED_SERIALIZER_PREFIX)
        context = {'request': self.context['request']}
        return serializer(obj.assigned_object, context=context).data

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
