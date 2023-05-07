from django import forms
from netbox.forms import NetBoxModelBulkEditForm

from ..models import SecretRole


class SecretRoleBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(queryset=SecretRole.objects.all(), widget=forms.MultipleHiddenInput)
    description = forms.CharField(max_length=200, required=False)

    model = SecretRole

    class Meta:
        nullable_fields = ['description']
