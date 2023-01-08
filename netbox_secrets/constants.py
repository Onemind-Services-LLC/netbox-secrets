from django.conf import settings
from django.db.models import Q

plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets')

#
# Secrets
#

SECRET_ASSIGNABLE_MODELS = Q()
for app_model in plugin_settings.get('apps'):
    app_label, model = app_model.split('.')
    SECRET_ASSIGNABLE_MODELS |= Q(app_label=app_label, model=model)

SECRET_PLAINTEXT_MAX_LENGTH = 65535
