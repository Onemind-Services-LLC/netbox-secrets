from django import template
from django.apps import apps
from django.urls import NoReverseMatch, reverse

from extras.plugins import PluginConfig
from utilities.forms import TableConfigForm

register = template.Library()


def _resolve_namespace(instance):
    """
    Get the appropriate namespace for the app based on whether it is a Plugin or base application
    """

    app = apps.get_app_config(instance._meta.app_label)
    if isinstance(app, PluginConfig):
        return f'plugins:{app.label}'
    return f'{app.label}'


def _get_plugin_viewname(instance, action=None):
    """
    Return the appropriate viewname for adding, editing, viewing changelog or deleting an instance.
    """

    # Validate action
    assert action in ('add', 'edit', 'delete', 'list', 'changelog')
    app_label = _resolve_namespace(instance)
    print(f'{app_label}')
    if action is not None:
        viewname = f'{app_label}:{instance._meta.model_name}_{action}'
    else:
        viewname = f'{app_label}:{instance._meta.model_name}'
    print(f'{app_label}:{viewname}')
    return viewname


@register.filter()
def validated_plugin_viewname(model, action):
    """
    Return the view name for the given model and action if valid, or None if invalid.
    """
    namespace = _resolve_namespace(model)
    viewname = f'{namespace}:{model._meta.model_name}_{action}'
    try:
        # Validate and return the view name. We don't return the actual URL yet because many of the templates
        # are written to pass a name to {% url %}.
        reverse(viewname)
        return viewname
    except NoReverseMatch:
        return None
