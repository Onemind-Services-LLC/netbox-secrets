# Remove first comment(#) on each line to implement this working logging example.
# Add LOGLEVEL environment variable to netbox if you use this example & want a different log level.
from os import environ

# Set LOGLEVEL in netbox.env or docker-compose.overide.yml to override a logging level of INFO.
LOGLEVEL = environ.get("LOGLEVEL", "INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
}
