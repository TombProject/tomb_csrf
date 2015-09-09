from pyramid.events import ContextFound
from tomb_csrf.csrf import check_csrf
from collections import defaultdict


class CSRFConfig:
    def __init__(self):
        self.origin_schemes = ['https', 'http']
        self.route_exemptions = set()
        self.route_origins = defaultdict(set)
        self.global_origins = set()


def set_origin_schemes(config, origin_schemes):
    config.registry.csrf_config.origin_schemes = set(origin_schemes)


def disable_csrf(config, route_name):
    config.registry.csrf_config.route_exemptions.add(route_name)


def add_csrf_origin(config, origin, route=None):
    """
    This adds other acceptable origins but assumes they are same scheme
    and port
    """
    if route is None:
        config.registry.csrf_config.global_origins.add(origin)
    else:
        config.registry.csrf_config.route_origins[origin].add(route)


def includeme(config):
    config.add_subscriber(check_csrf, ContextFound)
    config.add_directive('set_origin_schemes', set_origin_schemes)
    config.add_directive('disable_csrf', disable_csrf)
    config.add_directive('add_csrf_origin', add_csrf_origin)
    config.registry.csrf_config = CSRFConfig()
