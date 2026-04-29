FROM ckan/ckan-dev:2.11.4-py3.10

USER root
WORKDIR /srv/ckanext-pen

COPY requirements.txt setup.py setup.cfg README.md LICENSE MANIFEST.in ./
COPY ckanext ./ckanext
RUN pip install --no-cache-dir -e .

COPY docker/test/run-tests.sh /usr/local/bin/ckanext-pen-run-tests
RUN chmod +x /usr/local/bin/ckanext-pen-run-tests

CMD ["ckanext-pen-run-tests"]
