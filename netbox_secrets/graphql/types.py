from typing import Annotated, List

import strawberry
import strawberry_django

from netbox.graphql.types import NetBoxObjectType
from ..models import *
from .filters import *

__all__ = [
    'SecretRoleType',
    'SecretType',
]


@strawberry_django.type(SecretRole, fields="__all__", filters=SecretRoleFilter)
class SecretRoleType(NetBoxObjectType):
    name: str
    slug: str
    description: str


@strawberry_django.type(Secret, fields="__all__", filters=SecretFilter)
class SecretType(NetBoxObjectType):
    role: Annotated['SecretRoleType', strawberry.lazy('netbox_secrets.graphql.types')]
    name: str
    ciphertext: bool
    description: str
