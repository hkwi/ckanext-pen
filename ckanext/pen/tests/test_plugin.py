from urllib.parse import urlparse

import pytest
from flask import redirect

import ckan.model as model
from ckan.plugins import plugin_loaded

import ckanext.pen.plugin as pen_plugin


pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "pen"),
    pytest.mark.ckan_config("ckanext.pen.idp.client_id", "test-client"),
    pytest.mark.ckan_config("ckanext.pen.idp.client_secret", "test-secret"),
    pytest.mark.ckan_config(
        "ckanext.pen.idp.server_metadata_url",
        "https://idp.example.test/.well-known/openid-configuration",
    ),
    pytest.mark.ckan_config("ckanext.pen.idp.scope", "openid email profile"),
    pytest.mark.ckan_config("ckanext.pen.idp.callback", "/pen/callback"),
    pytest.mark.ckan_config("ckanext.pen.idp.claim_source", "id_token"),
    pytest.mark.ckan_config("ckanext.pen.idp.name_claim", "preferred_username"),
    pytest.mark.ckan_config("ckanext.pen.idp.email_claim", "email"),
    pytest.mark.ckan_config("ckanext.pen.idp.fullname_claim", "name"),
    pytest.mark.ckan_config("ckanext.pen.idp.groups_claim", "groups"),
    pytest.mark.ckan_config("ckanext.pen.idp.autogroup", ".*"),
    pytest.mark.ckan_config("ckanext.pen.idp.autoungroup", ".*"),
    pytest.mark.usefixtures("with_plugins"),
]


class FakeIdentityProvider:
    def __init__(self, token, oauth_calls):
        self.token = token
        self.oauth_calls = oauth_calls

    def authorize_redirect(self, redirect_uri):
        self.oauth_calls["redirect_uri"] = redirect_uri
        return redirect("/pen/callback")

    def authorize_access_token(self):
        self.oauth_calls["authorize_access_token"] += 1
        return self.token

    def userinfo(self):
        return self.token["userinfo"]


@pytest.fixture
def token():
    return {
        "access_token": "test-access-token",
        "userinfo": {
            "preferred_username": "alice",
            "email": "alice@example.test",
            "name": "Alice Example",
            "groups": ["publishers", "editors"],
        },
    }


@pytest.fixture
def oauth_calls():
    return {"authorize_access_token": 0}


@pytest.fixture
def fake_identity_provider(monkeypatch, token, oauth_calls):
    fake_idp = FakeIdentityProvider(token, oauth_calls)
    monkeypatch.setattr(
        pen_plugin.oauth,
        "create_client",
        lambda name: fake_idp if name == "idp" else None,
    )
    return fake_idp


def path_from_location(location):
    parsed = urlparse(location)
    if parsed.query:
        return f"{parsed.path}?{parsed.query}"
    return parsed.path


@pytest.mark.e2e
@pytest.mark.usefixtures("clean_db", "fake_identity_provider")
def test_oidc_login_creates_user_and_syncs_groups(app, token, oauth_calls):
    assert plugin_loaded("pen")

    client = app.test_client()

    response = client.get(
        "/user/login?came_from=/dataset",
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.location.endswith("/pen/callback")
    assert oauth_calls["redirect_uri"].endswith("/pen/callback")

    response = client.get(
        path_from_location(response.location),
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.location.endswith("/dataset")
    assert oauth_calls["authorize_access_token"] == 1

    user = model.User.by_name("alice")
    assert user is not None
    assert user.email == "alice@example.test"
    assert user.fullname == "Alice Example"

    group_names = {group.name for group in user.get_groups()}
    assert group_names == {"publishers", "editors"}
    assert model.Group.by_name("publishers").is_organization
    assert model.Group.by_name("editors").is_organization

    token["userinfo"]["groups"] = ["publishers"]

    response = client.get(
        "/user/login?came_from=/dataset",
        follow_redirects=False,
    )
    assert response.status_code == 302
    response = client.get(path_from_location(response.location), follow_redirects=False)
    assert response.status_code == 302

    model.Session.expire_all()
    user = model.User.by_name("alice")
    group_names = {group.name for group in user.get_groups()}
    assert group_names == {"publishers"}
