import os

from _pytest.fixtures import fixture

from keycloak_scanner.logging.http_logging import httpclient_logging_patch

# use it for debug, but this make start_test fail
# httpclient_logging_patch()


@fixture
def base_url() -> str:
    return 'http://localhost:8080'


@fixture
def proxy() -> str:
    if os.getenv('PROXY'):
        return os.getenv('PROXY')
