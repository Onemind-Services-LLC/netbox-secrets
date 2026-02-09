from django.conf import settings
from django.db.models import Q

# Plugin configuration
_plugin_settings = settings.PLUGINS_CONFIG.get("netbox_secrets", {})

# Secrets configuration
SECRET_PLAINTEXT_MAX_LENGTH = 65535
CENSOR_MASTER_KEY = "********"
CENSOR_MASTER_KEY_CHANGED = "***CHANGED***"

# Session configuration
SESSION_COOKIE_NAME = "netbox_secrets_sessionid"


# Build assignable models Q filter from plugin config
def get_assignable_models_filter() -> Q:
    """Construct Q filter for models that can have secrets assigned."""
    q_filter = Q()
    for app_model in _plugin_settings.get("apps", []):
        try:
            app_label, model = app_model.split(".", 1)
            q_filter |= Q(app_label=app_label, model=model)
        except ValueError:
            continue  # Skip malformed entries
    return q_filter


SECRET_ASSIGNABLE_MODELS = get_assignable_models_filter()

# Key generation settings
DEFAULT_KEY_SIZE = 2048
MIN_KEY_SIZE = 2048
MAX_KEY_SIZE = 8192
KEY_SIZE_INCREMENT = 256
