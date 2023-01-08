import django_filters
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet

from .constants import SECRET_ASSIGNABLE_MODELS
from .models import Secret, SecretRole

__all__ = (
    'SecretFilterSet',
    'SecretRoleFilterSet',
)


class SecretRoleFilterSet(NetBoxModelFilterSet):
    q = django_filters.CharFilter(
        method='search',
        label='Search',
    )
    name = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        field_name='name'
    )

    class Meta:
        model = SecretRole
        fields = ['id', 'name', 'slug']

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) |
            Q(slug__icontains=value)
        )


class SecretFilterSet(NetBoxModelFilterSet):
    q = django_filters.CharFilter(
        method='search',
        label='Search',
    )

    name = django_filters.ModelMultipleChoiceFilter(
        queryset=Secret.objects.all(),
        field_name='name',
        label='Name',
    )

    role_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        label='Role (ID)',
    )
    role = django_filters.ModelMultipleChoiceFilter(
        field_name='role__slug',
        queryset=SecretRole.objects.all(),
        to_field_name='slug',
        label='Role (slug)',
    )

    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name='assigned_object_type',
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        label='Object type (ID)',
    )

    class Meta:
        model = Secret
        fields = ['id', 'assigned_object_type_id', 'assigned_object_id', 'role_id', 'role', 'name']

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
        )
