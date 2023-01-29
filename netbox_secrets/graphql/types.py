from netbox.graphql.types import NetBoxObjectType, ObjectType

from netbox_secrets import filtersets, models

__all__ = [
    'SecretRoleType',
    'SecretType',
]


class SecretRoleType(ObjectType):
    class Meta:
        model = models.SecretRole
        fields = '__all__'
        filterset_class = filtersets.SecretRoleFilterSet


class SecretType(NetBoxObjectType):
    class Meta:
        model = models.Secret
        fields = '__all__'
        filterset_class = filtersets.SecretFilterSet
