from unittest.mock import MagicMock

import requests

from keycloak_scanner.scanners.clients_scanner import ClientScanner
from tests.mock_response import MockResponse


def test_perform():

    session = requests.Session()
    session.get = MagicMock(return_value=MockResponse(status_code=200, response={}))

    client_scanner = ClientScanner(clients=[], base_url='http://test', session=session)

    scan_properties = {
        'realms': {
            'master': '',
            'other': ''
        }
    }
    client_scanner.perform(scan_properties)

    assert scan_properties == {'clients': {}, 'realms': {'master': '', 'other': ''}}
