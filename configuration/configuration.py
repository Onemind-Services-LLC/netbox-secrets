####
## We recommend to not edit this file.
## Create separate files to overwrite the settings.
## See `extra.py` as an example.
####

from os import environ
from os.path import abspath, dirname

# For reference see https://netbox.readthedocs.io/en/stable/configuration/
# Based on https://github.com/netbox-community/netbox/blob/master/netbox/netbox/configuration.example.py

# Read secret from file
def _read_secret(secret_name, default=None):
    try:
        f = open('/run/secrets/' + secret_name, 'r', encoding='utf-8')
    except EnvironmentError:
        return default
    else:
        with f:
            return f.readline().strip()


_BASE_DIR = dirname(dirname(abspath(__file__)))

#########################
#                       #
#   Required settings   #
#                       #
#########################

# This is a list of valid fully-qualified domain names (FQDNs) for the NetBox server. NetBox will not permit write
# access to the server via any other hostnames. The first FQDN in the list will be treated as the preferred name.
#
# Example: ALLOWED_HOSTS = ['netbox.example.com', 'netbox.internal.local']
ALLOWED_HOSTS = environ.get('ALLOWED_HOSTS', '*').split(' ')

# PostgreSQL database configuration. See the Django documentation for a complete list of available parameters:
#   https://docs.djangoproject.com/en/stable/ref/settings/#databases
DATABASE = {
    'NAME': environ.get('DB_NAME', 'netbox'),  # Database name
    'USER': environ.get('DB_USER', ''),  # PostgreSQL username
    'PASSWORD': _read_secret('db_password', environ.get('DB_PASSWORD', '')),
    # PostgreSQL password
    'HOST': environ.get('DB_HOST', 'localhost'),  # Database server
    'PORT': environ.get('DB_PORT', ''),  # Database port (leave blank for default)
    'OPTIONS': {'sslmode': environ.get('DB_SSLMODE', 'prefer')},
    # Database connection SSLMODE
    'CONN_MAX_AGE': int(environ.get('DB_CONN_MAX_AGE', '300')),
    # Max database connection age
    'DISABLE_SERVER_SIDE_CURSORS': environ.get('DB_DISABLE_SERVER_SIDE_CURSORS', 'False').lower() == 'true',
    # Disable the use of server-side cursors transaction pooling
}

# Redis database settings. Redis is used for caching and for queuing background tasks such as webhook events. A separate
# configuration exists for each. Full connection details are required in both sections, and it is strongly recommended
# to use two separate database IDs.
REDIS = {
    'tasks': {
        'HOST': environ.get('REDIS_HOST', 'localhost'),
        'PORT': int(environ.get('REDIS_PORT', 6379)),
        'PASSWORD': _read_secret('redis_password', environ.get('REDIS_PASSWORD', '')),
        'DATABASE': int(environ.get('REDIS_DATABASE', 0)),
        'SSL': environ.get('REDIS_SSL', 'False').lower() == 'true',
        'INSECURE_SKIP_TLS_VERIFY': environ.get('REDIS_INSECURE_SKIP_TLS_VERIFY', 'False').lower() == 'true',
    },
    'caching': {
        'HOST': environ.get('REDIS_CACHE_HOST', environ.get('REDIS_HOST', 'localhost')),
        'PORT': int(environ.get('REDIS_CACHE_PORT', environ.get('REDIS_PORT', 6379))),
        'PASSWORD': _read_secret(
            'redis_cache_password', environ.get('REDIS_CACHE_PASSWORD', environ.get('REDIS_PASSWORD', ''))
        ),
        'DATABASE': int(environ.get('REDIS_CACHE_DATABASE', 1)),
        'SSL': environ.get('REDIS_CACHE_SSL', environ.get('REDIS_SSL', 'False')).lower() == 'true',
        'INSECURE_SKIP_TLS_VERIFY': environ.get(
            'REDIS_CACHE_INSECURE_SKIP_TLS_VERIFY', environ.get('REDIS_INSECURE_SKIP_TLS_VERIFY', 'False')
        ).lower()
        == 'true',
    },
}

# This key is used for secure generation of random numbers and strings. It must never be exposed outside of this file.
# For optimal security, SECRET_KEY should be at least 50 characters in length and contain a mix of letters, numbers, and
# symbols. NetBox will not run without this defined. For more information, see
# https://docs.djangoproject.com/en/stable/ref/settings/#std:setting-SECRET_KEY
SECRET_KEY = _read_secret('secret_key', environ.get('SECRET_KEY', ''))

DEVELOPER = True
