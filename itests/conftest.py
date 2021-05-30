import os
from pathlib import Path

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


@fixture
def callback_file(tmp_path: Path) -> Path:
    p = tmp_path / 'callback.txt'
    p.write_text('http://localhost:8080\nhttps://localhost:8443\n')
    return p
