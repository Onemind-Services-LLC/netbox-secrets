import django_filters
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.translation import gettext as _

from netbox.filtersets import NetBoxModelFilterSet
from tenancy.models import Contact
from utilities.filters import ContentTypeFilter, MultiValueCharFilter
from .constants import SECRET_ASSIGNABLE_MODELS
from .models import Secret, SecretRole, UserKey

__all__ = [
    'SecretFilterSet',
    'SecretRoleFilterSet',
]


class UserKeyFilterSet(NetBoxModelFilterSet):
    user_id = django_filters.ModelMultipleChoiceFilter(
        queryset=get_user_model().objects.all(),
        label=_('User (ID)'),
    )
    user = django_filters.ModelMultipleChoiceFilter(
        field_name='user__username',
        queryset=get_user_model().objects.all(),
        to_field_name='username',
        label=_('User (name)'),
    )

    class Meta:
        model = UserKey
        fields = [
            'id',
        ]

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(user__username__icontains=value))


class SecretRoleFilterSet(NetBoxModelFilterSet):
    name = MultiValueCharFilter(lookup_expr='iexact')

    class Meta:
        model = SecretRole
        fields = ['id', 'name', 'slug', 'description', 'comments']

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(slug__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value),
        )


class SecretFilterSet(NetBoxModelFilterSet):
    name = MultiValueCharFilter(lookup_expr='iexact')

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

    assigned_object_type = ContentTypeFilter()

    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(
        queryset=ContentType.objects.filter(SECRET_ASSIGNABLE_MODELS),
        label='Object type (ID)',
    )

    contact = django_filters.ModelMultipleChoiceFilter(
        field_name='contacts__contact',
        queryset=Contact.objects.all(),
        label=_('Contact'),
    )

    class Meta:
        model = Secret
        fields = [
            'id',
            'assigned_object_type',
            'assigned_object_type_id',
            'assigned_object_id',
            'role_id',
            'role',
            'name',
            'contact',
            '_object_repr',
            'description',
            'comments',
        ]

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(_object_repr__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value),
        )
