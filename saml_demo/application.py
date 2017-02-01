from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config

from pyramid.httpexceptions import (
    HTTPForbidden,
    HTTPFound,
)
from pyramid.security import (
    Allow,
    Authenticated,
    authenticated_userid,
    remember,
)

from saml2 import entity

from .okta import okta_saml_client

saml_client_factory = okta_saml_client


def main(global_config, **config):
    settings = global_config.copy()
    settings.update(config)

    config = Configurator(settings=settings)
    config.set_root_factory(Site)
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.set_authentication_policy(AuthTktAuthenticationPolicy(
        settings['secret']))
    config.scan('.')
    return config.make_wsgi_app()


class Site(object):
    __name__ = None
    __parent__ = None

    __acl__ = [
        (Allow, Authenticated, ('view',))
    ]

    def __init__(self, request):
        pass


@view_config(permission='view')
def helloworld(request):
    username = authenticated_userid(request)
    return Response('Hello {}!'.format(username))


@view_config(context=HTTPForbidden)
def saml_login(request):
    saml_client = saml_client_factory(request)
    reqid, info = saml_client.prepare_for_authenticate()
    for name, value in info['headers']:
        if name == 'Location':
            return HTTPFound(value)


@view_config(name='saml')
def saml_callback(request):
    saml_client = saml_client_factory(request)
    authn_response = saml_client.parse_authn_request_response(
        request.params['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text
    response = HTTPFound(request.resource_url(request.root))
    response.headerlist.extend(remember(request, username))
    return response
