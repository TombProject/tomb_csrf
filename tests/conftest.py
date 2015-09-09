import pytest


@pytest.fixture
def test_app():
    from webtest import TestApp
    from .fixtures.apps import test_app
    app = test_app({})
    app = TestApp(app)
    return app
