import graphene

from netbox.graphql.fields import ObjectField, ObjectListField
from .types import *


class SecretStoreQuery(graphene.ObjectType):
    secret = ObjectField(SecretType)
    secret_list = ObjectListField(SecretType)

    secretrole = ObjectField(SecretRoleType)
    secretrole_list = ObjectListField(SecretRoleType)
