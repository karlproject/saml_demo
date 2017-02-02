import requests

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
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import Issuer
from saml2.samlp import NameIDPolicy


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
    saml_client = get_saml_client(request)
    issuer = Issuer(
        text='Open Society Foundation',
        format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity')
    #name_id_policy = NameIDPolicy(
    #    allow_create='true',
    #    format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
    reqid, info = saml_client.prepare_for_authenticate(
        issuer=issuer,
        #version='2.0',
        #provider_name='google.com',
        #name_id_policy=name_id_policy,
    )
    for name, value in info['headers']:
        if name == 'Location':
            return HTTPFound(value)


@view_config(name='saml')
def saml_callback(request):
    saml_client = get_saml_client(request)
    authn_response = saml_client.parse_authn_request_response(
        request.params['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text
    response = HTTPFound(request.resource_url(request.root))
    response.headerlist.extend(remember(request, username))
    return response


def get_saml_client(request):
    metadata_url = request.registry.settings['saml_metadata_url']
    if metadata_url.startswith('file://'):
        path = metadata_url[7:]
        metadata = open(path).read()
    else:
        metadata = requests.get(metadata_url).text

    acs_url = request.resource_url(request.root, 'saml')

    settings = {
        'metadata': {
            'inline': [metadata],
            },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client
