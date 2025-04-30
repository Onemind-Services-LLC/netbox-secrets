ARG NETBOX_VARIANT=v4.2

FROM registry.onemindservices.com/netbox/tests:${NETBOX_VARIANT}

USER root

RUN mkdir -pv /plugins/netbox-secrets
COPY . /plugins/netbox-secrets

RUN pip install -e /plugins/netbox-secrets/

USER $USER
