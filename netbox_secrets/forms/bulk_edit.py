from django import forms
from netbox.forms import NetBoxModelBulkEditForm
from utilities.forms.fields import CommentField

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

    fieldsets = ((None, ('description',)),)

    class Meta:
        nullable_fields = ['description', 'comments']


class SecretBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(queryset=SecretRole.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(max_length=200, required=False)
    comments = CommentField()

    model = Secret

    fieldsets = ((None, ('description',)),)

    class Meta:
        nullable_fields = ['description', 'comments']
