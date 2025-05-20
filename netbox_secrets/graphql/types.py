from typing import Annotated, TYPE_CHECKING

import strawberry
import strawberry_django

from netbox.graphql.types import NetBoxObjectType, OrganizationalObjectType
from netbox_secrets.models import Secret, SecretRole
from .filters import *

if TYPE_CHECKING:
    from netbox.graphql.types import ContentTypeType

__all__ = [
    'SecretRoleType',
    'SecretType',
]


@strawberry_django.type(SecretRole, fields="__all__", filters=SecretRoleFilter, pagination=True)
class SecretRoleType(OrganizationalObjectType):
    pass


@strawberry_django.type(Secret, exclude=['ciphertext', 'hash', 'plaintext'], filters=SecretFilter, pagination=True)
class SecretType(NetBoxObjectType):
    role: Annotated['SecretRoleType', strawberry.lazy('netbox_secrets.graphql.types')]
    name: str
    description: str
    assigned_object_type: Annotated["ContentTypeType", strawberry.lazy('netbox.graphql.types')] | None

    @strawberry_django.field
    def role(self) -> Annotated["SecretRoleType", strawberry.lazy('netbox_secrets.graphql.types')] | None:
        return self.role
