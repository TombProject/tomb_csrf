from tomb_csrf.utils import SAFE_HEADERS
from pyramid.httpexceptions import HTTPForbidden
import urllib


REASON_NO_ORIGIN = "Origin checking failed - no Origin or Referer."
REASON_BAD_ORIGIN = "Origin checking failed - {} does not match {}."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."


class InvalidCSRF(HTTPForbidden):
    pass


def check_csrf(event):
    request = event.request
    csrf_config = request.registry.csrf_config

    # nothing to do here, we haven't matched any routes.
    if request.matched_route is None:
        return

    route_name = request.matched_route.name

    # We've turned CSRF checking off for this route
    if route_name in csrf_config.route_exemptions:
        return

    if request.method.upper() in SAFE_HEADERS:
        #TODO: Have we explicitly added CSRF to it?
        return

    # We want to run origin checking on supported schemes, a lot of browsers
    # don't pass proper origin/referer on HTTP so we want allow to turn that off
    if request.scheme in csrf_config.origin_schemes:
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")

        if origin is None and referer is None:
            raise InvalidCSRF(REASON_NO_ORIGIN)

        real_origin = origin or referer

        # Parse the origin and host for comparison
        originp = urllib.parse.urlparse(real_origin)
        hostp = urllib.parse.urlparse(request.host_url)
        full_origin = (originp.scheme, originp.hostname, originp.port)
        full_host = (hostp.scheme, hostp.hostname, hostp.port)

        route_exemptions = csrf_config.route_origins.get(originp.hostname, set())

        # We have allowed this route to work with this origin
        if (
                originp.hostname in csrf_config.global_origins or
                route_name in route_exemptions
        ):
            full_allowed_host = (hostp.scheme, originp.hostname, hostp.port)
            # Even though the origin is in the exemption list it was requested
            # on the wrong port/scheme so we should reject the request.
            if full_origin == full_allowed_host:
                return

            acceptable_origin = urllib.parse.urlunparse(
                full_allowed_host[:2] + ('', '', '', '')
            )
            reason = REASON_BAD_ORIGIN.format(
                origin, acceptable_origin
            )

            raise InvalidCSRF(reason)

        # We compare the full scheme, host, port combo that way we don't
        # get MITM attacks where https://example.com can make requests to
        # http://example.com/delete-the-database
        if full_origin != full_host:
            reason_origin = origin
# TODO: XHR might pass null?
#            if origin != "null":
#                reason_origin = urllib.parse.urlunparse(
#                    originp[:2] + ("", "", "", ""),
#                )

            reason = REASON_BAD_ORIGIN.format(
                reason_origin, request.host_url,
            )

            raise InvalidCSRF(reason)
