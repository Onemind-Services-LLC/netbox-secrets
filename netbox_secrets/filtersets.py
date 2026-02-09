import django_filters
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.translation import gettext as _

from netbox.filtersets import NestedGroupModelFilterSet, NetBoxModelFilterSet, PrimaryModelFilterSet
from tenancy.filtersets import ContactModelFilterSet
from users.models import User
from utilities.filters import ContentTypeFilter, TreeNodeMultipleChoiceFilter
from utilities.filtersets import register_filterset
from .models import Secret, SecretRole, UserKey

__all__ = [
    'SecretFilterSet',
    'SecretRoleFilterSet',
    'UserKeyFilterSet',
]


@register_filterset
class UserKeyFilterSet(NetBoxModelFilterSet):
    user_id = django_filters.ModelMultipleChoiceFilter(
        queryset=User.objects.all(),
        label=_('User (ID)'),
    )
    user = django_filters.ModelMultipleChoiceFilter(
        field_name='user__username',
        queryset=User.objects.all(),
        to_field_name='username',
        label=_('User (name)'),
    )

    class Meta:
        model = UserKey
        fields = ('id',)

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(user__username__icontains=value))


@register_filterset
class SecretRoleFilterSet(NestedGroupModelFilterSet):
    parent_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        label=_('Parent secret role (ID)'),
    )
    parent = django_filters.ModelMultipleChoiceFilter(
        field_name='parent__slug',
        queryset=SecretRole.objects.all(),
        to_field_name='slug',
        label=_('Parent secret role (slug)'),
    )
    ancestor_id = TreeNodeMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        field_name='parent',
        lookup_expr='in',
        label=_('Secret role (ID)'),
    )
    ancestor = TreeNodeMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        field_name='parent',
        lookup_expr='in',
        to_field_name='slug',
        label=_('Secret role (slug)'),
    )

    class Meta:
        model = SecretRole
        fields = ('id', 'name', 'slug', 'description')


@register_filterset
class SecretFilterSet(PrimaryModelFilterSet, ContactModelFilterSet):
    assigned_object_type = ContentTypeFilter()
    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(queryset=ContentType.objects.all())
    role_id = django_filters.ModelMultipleChoiceFilter(
        queryset=SecretRole.objects.all(),
        label=_('Role (ID)'),
    )
    role = django_filters.ModelMultipleChoiceFilter(
        field_name='role__slug',
        queryset=SecretRole.objects.all(),
        to_field_name='slug',
        label=_('Role (slug)'),
    )

    class Meta:
        model = Secret
        fields = ('id', 'name', 'assigned_object_id', '_object_repr')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(_object_repr__icontains=value) | Q(description__icontains=value)
        )
