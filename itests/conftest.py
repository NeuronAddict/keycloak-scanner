import requests
from _pytest.fixtures import fixture

from keycloak_scanner.logging.http_logging import httpclient_logging_patch

# use it for debug, but this make start_test fail
# httpclient_logging_patch()

@fixture
def base_url():
    return 'http://localhost:8080'


@fixture
def session() -> requests.Session:
    return requests.session()
