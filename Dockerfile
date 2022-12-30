ARG NETBOX_VARIANT=v3.3

FROM registry.tangience.net/netbox/netbox:${NETBOX_VARIANT}

USER root

# Remove pre-installed plugin
RUN rm -rf /usr/local/lib/python3.10/site-packages/netbox_secrets

RUN mkdir -pv /plugins/netbox-secrets
COPY . /plugins/netbox-secrets

RUN python3 /plugins/netbox-secrets/setup.py develop
RUN cp -rf /plugins/netbox-secrets/netbox_secrets/ /usr/local/lib/python3.10/site-packages/netbox_secrets

USER $USER
