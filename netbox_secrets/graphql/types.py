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
        fields = [
            'id',
            'name',
            'description',
            'role',
            'assigned_object_type',
            'assigned_object_id',
            'comments',
            'tags',
            'created',
            'last_updated',
        ]
        filterset_class = filtersets.SecretFilterSet
