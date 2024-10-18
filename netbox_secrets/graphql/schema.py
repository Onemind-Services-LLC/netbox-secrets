from typing import List

import strawberry
import strawberry_django

from .types import *


@strawberry.type(name='Query')
class NetboxSecretsQuery:
    secret_roles: List[SecretRoleType] = strawberry_django.field()
    secret_roles_list: List[SecretRoleType] = strawberry_django.field()

    secrets: List[SecretType] = strawberry_django.field()
    secrets_list: List[SecretType] = strawberry_django.field()
