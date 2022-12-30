#!/bin/bash
# Runs the NetBox plugin unit tests
# Usage:
#   ./test.sh latest
#   ./test.sh v2.9.7
#   ./test.sh develop-2.10

# exit when a command exits with an exit code != 0
set -e

# NETBOX_VARIANT is used by `Dockerfile` to determine the tag
NETBOX_VARIANT="${1-latest}"

# The docker compose command to use
doco="docker compose --file docker-compose.yml"

test_netbox_unit_tests() {
  echo "⏱  Running NetBox Unit Tests"
  $doco run --rm netbox python manage.py test netbox_secrets --keepdb
}

test_cleanup() {
  echo "💣  Cleaning Up"
  $doco down -v
  $doco rm -fsv
  docker image rm docker.io/library/netbox-secrets-netbox || echo ''
}

export NETBOX_VARIANT=${NETBOX_VARIANT}

echo "🐳🐳🐳  Start testing '${NETBOX_VARIANT}'"

# Make sure the cleanup script is executed
trap test_cleanup EXIT ERR
test_netbox_unit_tests

echo "🐳🐳🐳  Done testing '${NETBOX_VARIANT}'"
