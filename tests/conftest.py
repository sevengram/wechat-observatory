import pytest

from observatory import create_app


@pytest.fixture
def app():
  app = create_app({
    'TESTING': True,
    'DEBUG': False,
    'SIGN_KEY': 'fake_sign_key',
  })

  yield app


@pytest.fixture
def client(app):
  return app.test_client()


@pytest.fixture
def runner(app):
  return app.test_cli_runner()
