from netbox_secretstore import filtersets, models
from netbox.graphql.types import ObjectType, NetBoxObjectType

__all__ = (
    'SecretRoleType',
    'SecretType',
)


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
