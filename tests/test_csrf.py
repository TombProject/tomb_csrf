import pytest
from tomb_csrf.utils import SAFE_HEADERS, UNSAFE_HEADERS

@pytest.mark.unit
@pytest.mark.parametrize('request_method', SAFE_HEADERS)
def test_safe_request_methods_no_csrf(test_app, request_method):
    url = request_method.lower()
    method = request_method.upper()
    response = test_app.request('/%s' % url, method=method)

    assert response.status_int == 200


@pytest.mark.unit
@pytest.mark.parametrize('request_method', UNSAFE_HEADERS)
def test_unsafe_request_methods_no_origin(test_app, request_method):
    url = request_method.lower()
    method = request_method.upper()
    response = test_app.request(
        '/%s' % url,
        method=method,
        expect_errors=True
    )
    msg = b'Origin checking failed - no Origin or Referer.'

    assert response.status_int == 403
    assert msg in response.body


@pytest.mark.unit
@pytest.mark.parametrize('request_method', UNSAFE_HEADERS)
def test_unsafe_request_methods_good_origin(test_app, request_method):
    headers = {
        'Origin': 'http://localhost'
    }

    url = request_method.lower()
    method = request_method.upper()
    response = test_app.request(
        '/%s' % url,
        method=method,
        headers=headers,
        expect_errors=True
    )

    assert response.status_int == 200


@pytest.mark.unit
@pytest.mark.parametrize('request_method', UNSAFE_HEADERS)
def test_unsafe_request_methods_bad_origin(test_app, request_method):
    headers = {
        'Origin': 'http://localmonkey'
    }

    url = request_method.lower()
    method = request_method.upper()
    response = test_app.request(
        '/%s' % url,
        method=method,
        headers=headers,
        expect_errors=True
    )

    msg = b'http://localmonkey does not match http://localhost'
    assert response.status_int == 403
    assert msg in response.body


@pytest.mark.unit
def test_unsafe_request_methods_exempt(test_app):
    headers = {
        'Origin': 'http://localmonkey.com'
    }

    url = '/exempt'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
    )

    assert response.status_int == 200


@pytest.mark.unit
def test_unsafe_request_methods_bad_url_no_csrf(test_app):
    headers = {
        'Origin': 'http://localmonkey.com'
    }

    url = '/boomshakalaka123'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
        expect_errors=True
    )

    assert response.status_int == 404


@pytest.mark.unit
def test_unsafe_request_methods_global_allowed_origin(test_app):
    headers = {
        'Origin': 'http://localmonkey.com'
    }

    url = '/global_origin'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
    )

    assert response.status_int == 200


@pytest.mark.unit
def test_unsafe_request_methods_global_allowed_origin_bad_scheme(test_app):
    headers = {
        'Origin': 'https://localmonkey.com'
    }

    url = '/global_origin'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
        expect_errors=True
    )

    msg = b'https://localmonkey.com does not match http://localmonkey.com'
    assert response.status_int == 403
    assert msg in response.body


@pytest.mark.unit
def test_unsafe_request_methods_scoped_allowed_origin(test_app):
    headers = {
        'Origin': 'http://remotemonkey.com'
    }

    url = '/scoped_origin'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
    )

    assert response.status_int == 200


@pytest.mark.unit
def test_unsafe_request_methods_scoped_allowed_origin_bad_scheme(test_app):
    headers = {
        'Origin': 'https://remotemonkey.com'
    }

    url = '/scoped_origin'
    method = 'POST'
    response = test_app.request(
        url,
        method=method,
        headers=headers,
        expect_errors=True
    )

    msg = b'https://remotemonkey.com does not match http://remotemonkey.com'
    assert response.status_int == 403
    assert msg in response.body
