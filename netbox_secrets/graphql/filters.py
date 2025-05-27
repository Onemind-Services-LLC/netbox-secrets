from typing import Annotated, TYPE_CHECKING

import strawberry
import strawberry_django
from strawberry.scalars import ID
from strawberry_django import FilterLookup

from netbox.graphql.filter_mixins import (
    OrganizationalModelFilterMixin,
    PrimaryModelFilterMixin,
)
from ..models import *

if TYPE_CHECKING:
    from core.graphql.filters import ContentTypeFilter

__all__ = [
    'SecretFilter',
    'SecretRoleFilter',
]


@strawberry_django.filter_type(SecretRole, lookups=True)
class SecretRoleFilter(OrganizationalModelFilterMixin):
    pass


@strawberry_django.filter_type(Secret, lookups=True)
class SecretFilter(PrimaryModelFilterMixin):
    name: FilterLookup[str] | None = strawberry_django.filter_field()
    role: Annotated[
        'SecretRoleFilter', strawberry.lazy('netbox_secrets.graphql.filters')
    ] | None = strawberry_django.filter_field()
    role_id: ID | None = strawberry_django.filter_field()
    assigned_object_type: Annotated[
        'ContentTypeFilter', strawberry.lazy('core.graphql.filters')
    ] | None = strawberry_django.filter_field()
    assigned_object_id: ID | None = strawberry_django.filter_field()
