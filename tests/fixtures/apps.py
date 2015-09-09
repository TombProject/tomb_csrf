from pyramid.config import Configurator
from pyramid.response import Response


def test_view(request):
    return Response('Hello World')


def test_app(global_config, **settings):
    config = Configurator(settings=settings)
    config.include('tomb_csrf')

    # Safe routes
    # "GET", "HEAD", "OPTIONS", "TRACE"
    config.add_route('GET', '/get', request_method='GET')
    config.add_route('HEAD', '/head', request_method='HEAD')
    config.add_route('OPTIONS', '/options', request_method='OPTIONS')
    config.add_route('TRACE', '/trace', request_method='TRACE')

    # Unsafe routes
    # POST, PUT, DELETE
    config.add_route('POST', '/post', request_method='POST')
    config.add_route('PUT', '/put', request_method='PUT')
    config.add_route('DELETE', '/delete', request_method='DELETE')

    # Exempt Routes
    config.add_route('csrf_exempt', '/exempt')
    config.add_route('global_origin', '/global_origin')
    config.add_route('scoped_origin', '/scoped_origin')

    # Allowed Origin Route
    routes = [
        'GET', 'HEAD', 'OPTIONS', 'TRACE', 'POST', 'PUT', 'DELETE',
        'csrf_exempt', 'scoped_origin', 'global_origin'
    ]

    for route in routes:
        config.add_view(test_view, route_name=route)

    # disable csrf on a single route
    config.disable_csrf('csrf_exempt')

    # adds a global allowed origin
    config.add_csrf_origin('localmonkey.com')

    # adds an origin for a single route
    config.add_csrf_origin('remotemonkey.com', 'scoped_origin')
    config.set_origin_schemes(['http', 'https'])

    return config.make_wsgi_app()
