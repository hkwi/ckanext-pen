FROM ckan/ckan-base:2.11.6

USER root
WORKDIR /srv/ckanext-pen

COPY requirements.txt pyproject.toml setup.py setup.cfg README.md LICENSE MANIFEST.in ./
COPY ckanext ./ckanext
RUN pip install --no-cache-dir -e .
# ckan-base (production base) does not ship the test toolchain; install the
# minimum needed to run `pytest --ckan-ini=test.ini` (the ckan pytest
# fixtures come from the CKAN source tree at /srv/app/src/ckan, not from
# a separate package).
RUN pip install --no-cache-dir pytest factory-boy pytest-factoryboy

COPY docker/test/run-tests.sh /usr/local/bin/ckanext-pen-run-tests
RUN chmod +x /usr/local/bin/ckanext-pen-run-tests

CMD ["ckanext-pen-run-tests"]
