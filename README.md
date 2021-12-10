Netbox Secret Store
---

This is the continuation of the secrets app.

Installation
----

* Install NetBox as per NetBox documentation
* Add to local_requirements.txt:
  * `netbox-plugin-extensions`
  * `netbox-secretstore`
* Install requirements: `./venv/bin/pip install -r local_requirements.txt`
* Add to PLUGINS in NetBox configuration:
  * `'netbox_plugin_extensions',`
  * `'netbox_secretstore',`
* Run migration: `./venv/bin/python netbox/manage.py migrate`
* Run collectstatic: `./venv/bin/python netbox/manage.py collectstatic --no-input`

