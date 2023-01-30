from django.contrib.contenttypes.models import ContentType
from drf_yasg.utils import swagger_serializer_method
from netbox.api.fields import ContentTypeField
from netbox.api.serializers import NetBoxModelSerializer
from netbox.constants import NESTED_SERIALIZER_PREFIX
from rest_framework import serializers
from utilities.api import get_serializer_for_model

from ..constants import SECRET_ASSIGNABLE_MODELS
from ..models import Secret, SecretRole, UserKey
from .nested_serializers import *

#
# User Key
#


class UserKeySerializer(serializers.ModelSerializer):
    public_key = serializers.CharField()
    private_key = serializers.CharField(
        write_only=True,
    )

    display = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = UserKey
        fields = [
            'pk',
            'id',
            'display',
            'public_key',
            'private_key',
            'created',
            'last_updated',
            'is_active',
            'is_filled',
        ]

    def get_display(self, obj):
        return str(obj)


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
            'tags',
            'custom_fields',
            'created',
            'last_updated',
        ]
        validators = []

    @swagger_serializer_method(serializer_or_field=serializers.DictField)
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
