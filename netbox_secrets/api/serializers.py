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
