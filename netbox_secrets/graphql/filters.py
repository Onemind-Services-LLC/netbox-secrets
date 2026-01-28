from typing import Annotated, TYPE_CHECKING

import strawberry
import strawberry_django
from strawberry.scalars import ID
from strawberry_django import FilterLookup

try:
    from netbox.graphql.filters import (
        OrganizationalModelFilter,
        PrimaryModelFilter,
    )
except ImportError:  # NetBox < 4.5
    from netbox.graphql.filter_mixins import (
        OrganizationalModelFilterMixin as OrganizationalModelFilter,
        PrimaryModelFilterMixin as PrimaryModelFilter,
    )
from ..models import *

if TYPE_CHECKING:
    from core.graphql.filters import ContentTypeFilter

__all__ = [
    'SecretFilter',
    'SecretRoleFilter',
]


@strawberry_django.filter_type(SecretRole, lookups=True)
class SecretRoleFilter(OrganizationalModelFilter):
    pass


@strawberry_django.filter_type(Secret, lookups=True)
class SecretFilter(PrimaryModelFilter):
    name: FilterLookup[str] | None = strawberry_django.filter_field()
    role: Annotated[
        'SecretRoleFilter', strawberry.lazy('netbox_secrets.graphql.filters')
    ] | None = strawberry_django.filter_field()
    role_id: ID | None = strawberry_django.filter_field()
    assigned_object_type: Annotated[
        'ContentTypeFilter', strawberry.lazy('core.graphql.filters')
    ] | None = strawberry_django.filter_field()
    assigned_object_id: ID | None = strawberry_django.filter_field()
