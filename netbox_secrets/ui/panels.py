from django.utils.translation import gettext_lazy as _
from netbox.ui import panels, attrs


class SecretPanel(panels.ObjectAttributesPanel):
    title = _('Secret Attributes')

    assigned_object = attrs.RelatedObjectAttr('assigned_object', linkify=True)
    role = attrs.RelatedObjectAttr('role', linkify=True)
    name = attrs.TextAttr('name')
    description = attrs.TextAttr('description')


class SecretViewPanel(panels.ObjectPanel):
    template_name = 'netbox_secrets/secretview_modal.html'
