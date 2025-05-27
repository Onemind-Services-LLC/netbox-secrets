from typing import List

import strawberry
import strawberry_django

from .types import *


@strawberry.type(name='Query')
class NetboxSecretsQuery:
    secret_role: SecretRoleType = strawberry_django.field()
    secret_role_list: List[SecretRoleType] = strawberry_django.field()

    secret: SecretType = strawberry_django.field()
    secret_list: List[SecretType] = strawberry_django.field()
