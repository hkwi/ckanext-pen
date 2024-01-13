from typing import Any
import flask_login
import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import re
import logging
from ckan.config.declaration import Declaration, Key

from flask import Blueprint, request, session, current_app
from authlib.integrations.flask_client import OAuth

log = logging.getLogger(__name__)

import functools
import traceback
def trace_dump(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            traceback.print_exc()
            raise
    return wrapper

def autocommit(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        try:
            model.Session.commit()
        except:
            model.Session.rollback()
            raise
        return ret
    return wrapper

class ConfigKey(str):
    def __getattr__(self, name: str):
        return ConfigKey(f"{self}.{name}")
    
    def __call__(self):
        return str(self)

oauth = OAuth()
bp = Blueprint("pen", __name__)
ckey = ConfigKey("ckanext.pen")

@bp.before_app_request
def init_oauth():
    oauth.init_app(current_app)

class PenPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigDeclaration)

    def declare_config_options(self, declaration: Declaration, key: Key):
        idp = key.ckanext.pen.idp
        declaration.annotate("Pen config section")
        declaration.declare(
            idp.client_id,
            "some_client_id_string"
        ).set_description(
            "OpenID Connect shared client_id string"
        )
        declaration.declare(
            idp.client_secret,
            "some_client_secret_string"
        ).set_description(
            "OpenID Connect shared client_secret string"
        )
        declaration.declare(
            idp.server_metadata_url,
            "https://idp.example.org/.well-known/openid-configuration"
        ).set_description(
            "URL for .well-known/openid-configuration endpoint"
        )
        declaration.declare(
            idp.scope,
            "openid email profile"
        ).set_description(
            "scope"
        )
        declaration.declare(
            idp.callback,
            "/pen/callback"
        ).set_description(
            "client callback endpoint path on this ckan"
        )
        declaration.declare(
            idp.claim_source,
            "id_token"
        ).set_description(
            "user claim source. id_token or access_token or userinfo"
        )
        declaration.declare(
            idp.name_claim,
            "preferred_username"
        ).set_description(
            "claim name that is mapped to User.name database field"
        )
        declaration.declare(
            idp.email_claim,
            "email"
        ).set_description(
            "claim name that is mapped to User.email database field"
        )
        declaration.declare(
            idp.fullname_claim,
            "name"
        ).set_description(
            "claim name that is mapped to User.fullname database field"
        )
        declaration.declare(
            idp.groups_claim,
            "groups"
        ).set_description(
            '''claim name for group names.
            
            https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/#request-an-id-token-that-contains-the-groups-claim
            https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles
            '''
        )
        declaration.declare(
            idp.autogroup,
            ".*"
        ).set_description(
            '''Pattern for group name that will be created if missing.
            User will join to that group automatically'''
        )
        declaration.declare(
            idp.autoungroup,
            ".*"
        ).set_description(
            '''Pattern for group name. 
            User will leave to that group automatically if user does not 
            have that group name in authenticated groups claim.'''
        )

    plugins.implements(plugins.IConfigurable)

    def configure(self, config):
        self.config = config

        @bp.route(config[ckey.idp.callback]) 
        @trace_dump
        @autocommit
        def callback():
            idp = oauth.create_client("idp")
            token = idp.authorize_access_token()
            session[ckey.idp.token()] = token
            if config[ckey.idp.claim_source] == "userinfo":
                session[ckey.idp.userinfo()] = idp.userinfo()

            self._claims_sync()

            came_from = session.pop("came_from", None)
            if toolkit.h.url_is_local(came_from):
                return toolkit.redirect_to(came_from)
            return toolkit.redirect_to(toolkit.url_for(
                self.config["ckan.auth.route_after_login"]
            ))
    
    plugins.implements(plugins.IAuthenticator)

    def identify(self):
        user = self._userobj()
        if user:
            flask_login.login_user(user)
            toolkit.g.user = user.name

    @trace_dump
    def login(self):
        session["came_from"] = request.args.get("came_from")
        next = toolkit.url_for("pen.callback", _external=True)
        return oauth.create_client("idp").authorize_redirect(next)
    
    def logout(self):
        session.pop(ckey.idp.token, None)
        session.pop(ckey.idp.userinfo, None)

    def abort(self, *args, **kwargs):
        return args
        
    def authenticate(self, identity):
        # This method is for default login flow where identity contains username and password
        pass

    plugins.implements(plugins.IBlueprint)
    
    def get_blueprint(self):
        config = self.config
        oauth.register(
            "idp",
            client_id = config[ckey.idp.client_id],
            client_secret = config[ckey.idp.client_secret],
            server_metadata_url = config[ckey.idp.server_metadata_url],
            client_kwargs = dict(
                scope = config[ckey.idp.scope]
            )
        )
        return bp

    def _userobj(self, user_only=True):
        if ckey.idp.token not in session:
            return
        name_claim = self.config[ckey.idp.name_claim]
        return model.User.by_name(self._claims[name_claim])
    
    @property
    def _claims(self):
        claim_source = self.config[ckey.idp.claim_source]
        if claim_source == "id_token":
            return session[ckey.idp.token]["userinfo"] # token["userinfo"] is jwt-decoded-id_token
        elif claim_source == "access_token":
            # access_token may be jwt
            return session[ckey.idp.token]["access_token"] # XXX decode jwt
        elif claim_source == "userinfo":
            return session[ckey.idp.userinfo]
        else:
            return {}
    
    def _claims_sync(self):
        claims = self._claims
        userobj = self._userobj()
        if userobj is None:
            # autocreate User
            keys = dict(
                name=ckey.idp.name_claim,
                email=ckey.idp.email_claim,
                fullname=ckey.idp.fullname_claim
            )
            claim_keys = {k:self.config[v()] for k,v in keys.items()}
            args = {k:claims[v] for k,v in claim_keys.items() if v in claims}
            userobj = model.User(**args)
            model.Session.add(userobj)
            model.Session.flush() # assign .id
    
        autogroup = self.config[ckey.idp.autogroup]
        if autogroup:
            for g in self._claim_groups:
                if re.match(autogroup, g):
                    group = model.Group.by_name(g)
                    if group is None:
                        group = model.Group(
                            name=g, title=g, type="organization", is_organization=True,
                            description="created by ckanext-pen autogroup, synced with identity provider."
                        )
                        model.Session.add(group)
                        model.Session.flush() # assign .id
                    if not userobj.is_in_group(group.id):
                        member = model.Member(
                            table_name="user",
                            table_id=userobj.id,
                            capacity="member",
                            group=group,
                        )
                        model.Session.add(member)
        
        autoungroup = self.config[ckey.idp.autoungroup]
        if autoungroup:
            for group in userobj.get_groups():
                if re.match(autoungroup, group.name):
                    if group.name not in self._claim_groups:
                        q = model.Session.query(model.Member).filter(
                            table_name="user",
                            table_id=userobj.id,
                            group_id=group.id,
                        )
                        for member in q:
                            member.state = model.State.DELETED
                            model.Session.add(member)

    @property
    def _claim_groups(self):
        claims = self._claims

        groups_claim = self.config[ckey.idp.groups_claim]
        if groups_claim not in claims:
            log.warn("claim does not have groups claim.")
            return []
        
        groups = claims[groups_claim]
        if not isinstance(groups, (tuple,list)):
            log.warn("group claim must be list of string")
            return []
        
        for g in groups:
            if not isinstance(g, str):
                log.warn("groups claim must be list of string")
                return []
        
        return groups
