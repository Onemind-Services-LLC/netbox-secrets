from django import forms

from netbox.forms import NetBoxModelBulkEditForm
from utilities.forms.fields import CommentField
from utilities.forms.rendering import FieldSet
from ..models import Secret, SecretRole

__all__ = [
    'SecretRoleBulkEditForm',
    'SecretBulkEditForm',
]


class SecretRoleBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(queryset=SecretRole.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(max_length=200, required=False)
    comments = CommentField()

    model = SecretRole

    FieldSets = (FieldSet('description', name=None),)

    class Meta:
        nullable_fields = ['description', 'comments']


class SecretBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(queryset=SecretRole.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(max_length=200, required=False)
    comments = CommentField()

    model = Secret

    FieldSets = (FieldSet('description', name=None),)

    class Meta:
        nullable_fields = ['description', 'comments']
