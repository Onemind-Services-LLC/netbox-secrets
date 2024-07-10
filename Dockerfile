ARG NETBOX_VARIANT=v4.0

FROM netboxcommunity/netbox:${NETBOX_VARIANT}

RUN mkdir -pv /plugins/netbox-secrets
COPY . /plugins/netbox-secrets

RUN /opt/netbox/venv/bin/python3 /plugins/netbox-secrets/setup.py develop
RUN cp -rf /plugins/netbox-secrets/netbox_secrets/ /opt/netbox/venv/lib/python3.11/site-packages/netbox_secrets
