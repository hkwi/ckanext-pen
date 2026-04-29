#!/usr/bin/env bash
set -eu

cd /srv/ckanext-pen

ckan -c test.ini db init
pytest -q --ckan-ini=test.ini "$@"
