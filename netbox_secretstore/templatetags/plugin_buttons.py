from django import template
from django.urls import reverse

from extras.models import ExportTemplate
from utilities.utils import prepare_cloned_fields
from .plugin_helpers import _get_plugin_viewname

register = template.Library()


#
# Table buttons
#

@register.inclusion_tag('netbox_secretstore/buttons/tr_edit.html')
def tr_edit_button(instance, extra=None):
    viewname = _get_plugin_viewname(instance, 'edit')
    base_url = reverse(_get_plugin_viewname(instance, 'list'))
    url = reverse(viewname, kwargs={'pk': instance.pk})
    url = f'{url}?return_url={base_url}'

    if extra is not None:
        url = f'{url}{extra}'

    return {
        'url': url,
    }


@register.inclusion_tag('netbox_secretstore/buttons/tr_delete.html')
def tr_delete_button(instance, extra=None):
    viewname = _get_plugin_viewname(instance, 'delete')
    base_url = reverse(_get_plugin_viewname(instance, 'list'))
    url = reverse(viewname, kwargs={'pk': instance.pk})
    url = f'{url}?return_url={base_url}'

    if extra is not None:
        url = f'{url}{extra}'

    return {
        'url': url,
    }


@register.inclusion_tag('netbox_secretstore/buttons/tr_changelog.html')
def tr_changelog_button(instance):
    print(instance)
    viewname = _get_plugin_viewname(instance, 'changelog')
    print(viewname)
    url = reverse(viewname, kwargs={'pk': instance.pk})

    return {
        'url': url,
    }


#
# Instance buttons
#

@register.inclusion_tag('buttons/clone.html')
def clone_button(instance):
    url = reverse(_get_plugin_viewname(instance, 'add'))

    # Populate cloned field values
    param_string = prepare_cloned_fields(instance)
    if param_string:
        url = f'{url}?{param_string}'

    return {
        'url': url,
    }


@register.inclusion_tag('buttons/add.html')
def add_button(instance):
    viewname = _get_plugin_viewname(instance, 'edit')
    url = reverse(viewname, kwargs={'pk': instance.pk})

    return {
        'url': url,
    }


@register.inclusion_tag('buttons/edit.html')
def edit_button(instance):
    viewname = _get_plugin_viewname(instance, 'edit')
    url = reverse(viewname, kwargs={'pk': instance.pk})

    return {
        'url': url,
    }


@register.inclusion_tag('buttons/delete.html')
def delete_button(instance):
    viewname = _get_plugin_viewname(instance, 'delete')
    url = reverse(viewname, kwargs={'pk': instance.pk})

    return {
        'url': url,
    }
