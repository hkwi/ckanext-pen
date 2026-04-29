[![E2E](https://github.com/hkwi/ckanext-pen/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/hkwi/ckanext-pen/actions/workflows/e2e.yml)

# ckanext-pen

`ckanext-pen` is a CKAN extension that replaces the CKAN login flow with an
OpenID Connect login flow. It uses Authlib to authenticate with an external
identity provider, creates CKAN users from OIDC claims, and can synchronize OIDC
group claims into CKAN organizations.

## Requirements

| Component | Version used by this repository |
| --- | --- |
| CKAN | 2.11.4 in the Docker test image |
| Python | 3.10 in the Docker test image |
| Authlib | 1.7.0 |

CKAN 2.11 is the tested target. Other CKAN versions are not currently covered by
the test suite.

## Installation

Activate your CKAN virtual environment, then install the extension:

```sh
git clone https://github.com/hkwi/ckanext-pen.git
cd ckanext-pen
pip install -e .
```

Add `pen` to `ckan.plugins` in your CKAN configuration:

```ini
ckan.plugins = pen
```

Configure the OpenID Connect identity provider settings described below, then
restart CKAN.

## Configuration

Minimum OIDC configuration:

```ini
ckanext.pen.idp.client_id = your-client-id
ckanext.pen.idp.client_secret = your-client-secret
ckanext.pen.idp.server_metadata_url = https://idp.example.org/.well-known/openid-configuration
```

Optional settings and defaults:

| Setting | Default | Description |
| --- | --- | --- |
| `ckanext.pen.idp.scope` | `openid email profile` | OIDC scopes requested during login. |
| `ckanext.pen.idp.callback` | `/pen/callback` | Callback path registered in CKAN. Configure this path as the redirect URI path at the identity provider. |
| `ckanext.pen.idp.claim_source` | `id_token` | Source for user claims. `id_token` and `userinfo` are supported by the current implementation. `access_token` is declared but is not decoded as a JWT. |
| `ckanext.pen.idp.name_claim` | `preferred_username` | Claim mapped to `User.name`. |
| `ckanext.pen.idp.email_claim` | `email` | Claim mapped to `User.email`. |
| `ckanext.pen.idp.fullname_claim` | `name` | Claim mapped to `User.fullname`. |
| `ckanext.pen.idp.groups_claim` | `groups` | Claim containing a list of group or organization names. |
| `ckanext.pen.idp.autogroup` | `.*` | Regular expression for claim groups that should be created as CKAN organizations and assigned to the user. Set to an empty value to disable automatic joins. |
| `ckanext.pen.idp.autoungroup` | `.*` | Regular expression for existing organizations that should be removed from the user when missing from the current group claim. Set to an empty value to disable automatic removals. |

The callback URL sent to the identity provider is generated from CKAN's site URL
and the configured callback path. For the default callback, register:

```text
https://your-ckan.example.org/pen/callback
```

## Group Synchronization

When the configured `groups_claim` is present and contains a list of strings,
`ckanext-pen` compares those values with the user's CKAN organization
memberships.

Matching values from `autogroup` are created as CKAN organizations when missing,
and the user is added as a member. Matching values from `autoungroup` are removed
from the user when they no longer appear in the OIDC claims.

## Development

For development in an existing CKAN environment:

```sh
git clone https://github.com/hkwi/ckanext-pen.git
cd ckanext-pen
pip install -e .
```

The repository also contains a self-contained Docker Compose test environment
using CKAN 2.11.4, PostgreSQL, Solr, and Redis.

## Tests

Run the Docker Compose test suite:

```sh
docker compose -f docker-compose.test.yml build ckan-test
docker compose -f docker-compose.test.yml run --rm ckan-test
docker compose -f docker-compose.test.yml down --volumes --remove-orphans
```

The test container initializes the CKAN database and runs:

```sh
pytest -q --ckan-ini=test.ini
```

The suite includes an OIDC end-to-end test that exercises CKAN's `/user/login`
route, follows the callback, creates a CKAN user from OIDC claims, and verifies
organization membership synchronization. The identity provider is replaced with a
test double, so the test itself does not contact an external OIDC provider.

To run only the e2e test in an already prepared CKAN test environment:

```sh
pytest -m e2e --ckan-ini=test.ini
```

## Release

The package metadata lives in `setup.cfg`; update the version there before
building a release.

```sh
python -m pip install --upgrade setuptools wheel twine
python setup.py sdist bdist_wheel
twine check dist/*
twine upload dist/*
```

## License

[AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.en.html)
