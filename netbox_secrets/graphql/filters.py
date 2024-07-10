import strawberry_django
from netbox.graphql.filter_mixins import autotype_decorator, BaseFilterMixin

from ..models import *
from ..filtersets import *

__all__ = [
    'SecretFilter',
    'SecretRoleFilter',
]


@strawberry_django.filter(Secret, lookups=True)
@autotype_decorator(SecretFilterSet)
class SecretFilter(BaseFilterMixin):
    pass


@strawberry_django.filter(SecretRole, lookups=True)
@autotype_decorator(SecretRoleFilterSet)
class SecretRoleFilter(BaseFilterMixin):
    pass
