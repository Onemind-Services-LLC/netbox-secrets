from netbox.api.serializers import WritableNestedSerializer
from rest_framework import serializers

from ..models import *

__all__ = [
    'NestedSecretRoleSerializer',
    'NestedSecretSerializer',
    'NestedSessionKeySerializer',
    'NestedUserKeySerializer',
]


class NestedSecretSerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secret-detail')

    class Meta:
        model = Secret
        fields = ['id', 'url', 'display', 'name']


class NestedSecretRoleSerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:secretrole-detail')
    secret_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = SecretRole
        fields = ['id', 'url', 'display', 'name', 'slug', 'secret_count']


class NestedSessionKeySerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:sessionkey-detail')

    class Meta:
        model = SessionKey
        fields = ['id', 'url', 'display']


class NestedUserKeySerializer(WritableNestedSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_secrets-api:userkey-detail')

    class Meta:
        model = UserKey
        fields = ['id', 'url', 'display']
