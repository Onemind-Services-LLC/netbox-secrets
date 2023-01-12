# Netbox Secrets

This is the continuation of the [NetBox Secretstore](https://github.com/DanSheps/netbox-secretstore) app.

# Compatibility

| NetBox Version | Plugin Version |
|----------------|----------------|
| 3.3.x          | 1.4.x, 1.5.x   |
| 3.4.x          | 1.6.x          |

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
  - __Type__: `List`
  - __Description__: List of apps to enable
  - __Default__: `['dcim.device', 'virtualization.virtualmachine']`
- `display_default`
  - __Type__: `String`
  - __Description__: Where to display the secret on the detail page of the defined apps
  - __Default__: `left_page`
  - __Options__: `left_page`, `right_page`, `full_width_page`
- `display_setting`
  - __Type__: `Dict`
  - __Description__: Set display setting for concrete model
  - __Default__: `{}`
  - __Options__: `{'app.model': 'display_default'}`
  - __Example__: `{'dcim.device': 'full_width_page', 'virtualization.virtualmachine': 'right_page'}`
- `enable_contacts`
  - __Type__: `Boolean`
  - __Description__: Enable contacts for secret
  - __Default__: `False`
- `public_key_size`
  - __Type__: `Integer`
  - __Description__: Size of the public key
  - __Default__: `2048`
  - __Options__: `2048`, `4096`, `8192`
