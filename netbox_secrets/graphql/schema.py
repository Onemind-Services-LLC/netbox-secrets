from typing import List

import strawberry
import strawberry_django

from ..models import *
from .types import *


@strawberry.type
class NetboxSecretsQuery:
    @strawberry.field
    def secret_roles(self, id: int) -> List[SecretRoleType]:
        return SecretRole.objects.get(pk=id)

    secret_roles_list: List[SecretRoleType] = strawberry_django.field()

    @strawberry.field
    def secrets(self, id: int) -> List[SecretType]:
        return Secret.objects.get(pk=id)

    secrets_list: List[SecretType] = strawberry_django.field()
