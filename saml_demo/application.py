from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config


def main(global_config, **config):
    settings = global_config.copy()
    settings.update(config)

    config = Configurator(settings=settings)
    config.scan('.')
    return config.make_wsgi_app()


@view_config()
def helloworld(request):
    return Response('Hello World!')
