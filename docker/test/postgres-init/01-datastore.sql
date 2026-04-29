CREATE USER datastore_ro WITH PASSWORD 'datastore';
CREATE DATABASE datastore_test OWNER ckan;
GRANT CONNECT ON DATABASE datastore_test TO datastore_ro;
