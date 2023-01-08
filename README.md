# Netbox Secrets

This is the continuation of the [NetBox Secretstore](https://github.com/DanSheps/netbox-secretstore) app.

# Installation

* Install NetBox as per NetBox documentation
* Add to local_requirements.txt:
  * `git+https://github.com/Onemind-Services-LLC/netbox-secrets`
* Install requirements: `./venv/bin/pip install -r local_requirements.txt`
* Add to PLUGINS in NetBox configuration:
  * `'netbox_secrets',`
* Run migration: `./venv/bin/python netbox/manage.py migrate`
* Run collectstatic: `./venv/bin/python netbox/manage.py collectstatic --no-input`

# Configuration

The following options are available in the configuration file:

- `apps`
  - *Type*: `List`
  - *Description*: List of apps to enable
  - *Default*: `['dcim.device', 'virtualization.virtualmachine']`
- `display_default`
  - *Type*: `String`
  - *Description*: Where to display the secret on the detail page of the defined apps
  - *Default*: `left_page`, `right_page`, `full_width_page`
- `display_setting`
  - *Type*: `Dict`
  - *Description*: Set display setting for concrete model
  - *Default*: `{}`
  - *Options*: `{'app.model': 'display_default'}`
  - *Example*: `{'dcim.device': 'full_width_page', 'virtualization.virtualmachine': 'right_page'}`