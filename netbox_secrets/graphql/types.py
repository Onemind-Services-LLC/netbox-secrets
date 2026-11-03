from typing import Annotated, List, TYPE_CHECKING

import strawberry
import strawberry_django
from strawberry.scalars import ID

from extras.graphql.mixins import ContactsMixin
from netbox.graphql.types import NestedGroupObjectType, PrimaryObjectType, register_type
from netbox_secrets.models import Secret, SecretRole
from .filters import *

if TYPE_CHECKING:
    from core.graphql.filters import ContentTypeFilter

__all__ = [
    'SecretRoleType',
    'SecretType',
]


@register_type(Secret, exclude=['ciphertext', 'hash', 'plaintext'], filters=SecretFilter, pagination=True)
class SecretType(ContactsMixin, PrimaryObjectType):
    role: Annotated['SecretRoleType', strawberry.lazy('netbox_secrets.graphql.types')]
    assigned_object_type: Annotated[
        'ContentTypeFilter', strawberry.lazy('core.graphql.filters')
    ] | None = strawberry_django.filter_field()
    assigned_object_type_id: ID | None = strawberry_django.filter_field()
    assigned_object_id: ID | None = strawberry_django.filter_field()


@register_type(SecretRole, exclude=['path', 'sort_path'], filters=SecretRoleFilter, pagination=True)
class SecretRoleType(NestedGroupObjectType):
    parent: Annotated['SecretRoleType', strawberry.lazy('netbox_secrets.graphql.types')] | None

    secrets: List[SecretType]
    children: List[Annotated['SecretRoleType', strawberry.lazy('netbox_secrets.graphql.types')]]
