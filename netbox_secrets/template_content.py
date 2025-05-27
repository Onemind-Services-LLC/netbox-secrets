import logging

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.utils import OperationalError

from netbox.plugins import PluginTemplateExtension
from netbox.views import generic
from utilities.views import ViewTab, register_model_view
from .filtersets import SecretFilterSet
from .forms import SecretFilterForm
from .models import Secret
from .tables import SecretTable

logger = logging.getLogger(__name__)
plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets')
template_extensions = []


def secrets_panel(self):
    obj = self.context['object']
    for model in self.models:
        app_label, model = model.split('.')
        assigned_object_type = ContentType.objects.get(app_label=app_label, model=model).id

        return self.render(
            'netbox_secrets/inc/secrets_panel.html',
            extra_context={
                'secrets': Secret.objects.filter(assigned_object_type=assigned_object_type, assigned_object_id=obj.id),
            },
        )
    return None


def get_display_on(app_model):
    """Get preferred display location for app_model."""
    display_on = 'tab_view'  # Default fallback

    if display_default := plugin_settings.get('display_default'):
        display_on = display_default

    if display_setting := plugin_settings.get('display_setting'):
        display_on = display_setting.get(app_model, display_on)

    return display_on


def tab_view(_model):
    class ModelTabView(generic.ObjectChildrenView):
        queryset = _model.objects.all()
        child_model = Secret
        table = SecretTable
        filterset = SecretFilterSet
        filterset_form = SecretFilterForm
        tab = ViewTab(
            label='Secrets',
            badge=lambda obj: obj.secrets.count(),
            weight=500,
        )

        def get_children(self, request, parent):
            return self.child_model.objects.restrict(request.user, 'view').filter(
                assigned_object_type=ContentType.objects.get_for_model(parent),
                assigned_object_id=parent.pk,
            )

    register_model_view(_model, name='secrets')(ModelTabView)


def secret_add_button(_app_model):
    class Button(PluginTemplateExtension):
        models = [_app_model]

        def buttons(self):
            return self.render(
                'netbox_secrets/inc/secret_add_button.html',
            )

    return Button


# Generate plugin extensions for the defined classes
try:
    for app_model in plugin_settings.get('apps'):
        app_label, model = app_model.split('.')
        klass_name = f'{app_label}_{model}_plugin_template_extension'

        display = get_display_on(app_model)

        if display == 'tab_view':
            template_extensions.append(secret_add_button(app_model))
            tab_view(ContentType.objects.get(app_label=app_label, model=model).model_class())
        else:
            dynamic_klass = type(
                klass_name,
                (PluginTemplateExtension,),
                {'models': [app_model], get_display_on(app_model): secrets_panel},
            )
            template_extensions.append(dynamic_klass)
except OperationalError as e:
    # This happens when the database is not yet ready
    logger.warning(f'Database not ready, skipping plugin extensions: {e}')
except Exception as e:
    # Unexpected error
    raise Exception(f'Unexpected error: {e}')
