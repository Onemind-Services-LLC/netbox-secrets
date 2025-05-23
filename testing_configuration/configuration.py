###################################################################
#  This file serves as a base configuration for testing purposes  #
#  only. It is not intended for production use.                   #
###################################################################

ALLOWED_HOSTS = ["*"]

DATABASE = {
    "NAME": "netbox",
    "USER": "netbox",
    "PASSWORD": "netbox",
    "HOST": "localhost",
    "PORT": "",
    "CONN_MAX_AGE": 300,
}

PLUGINS = [
    "netbox_secrets",
]

PLUGINS_CONFIG = {  # type: ignore
    "netbox_secrets": {},
}

REDIS = {
    "tasks": {
        "HOST": "localhost",
        "PORT": 6379,
        "PASSWORD": "",
        "DATABASE": 0,
        "SSL": False,
    },
    "caching": {
        "HOST": "localhost",
        "PORT": 6379,
        "PASSWORD": "",
        "DATABASE": 1,
        "SSL": False,
    },
}

SECRET_KEY = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

DEFAULT_PERMISSIONS = {}

ALLOW_TOKEN_RETRIEVAL = True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True
}
