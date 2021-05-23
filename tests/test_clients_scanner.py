from unittest.mock import MagicMock

import requests
from requests import Session

from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client
from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict
from tests.mock_response import MockResponse


def test_perform(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm,
                 well_known_dict: WellKnownDict, client1: Client, client2: Client):

    client_scanner = ClientScanner(clients=['client1', 'client2'], base_url='http://localhost:8080', session=full_scan_mock_session)

    realms = [master_realm]

    result = client_scanner.perform(realms=realms, well_known_dict=well_known_dict)

    assert result == [
        client1, client2
    ]
