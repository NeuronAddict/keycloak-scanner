from unittest.mock import MagicMock

import requests
from pytest import fixture

from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner

from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner


class TestScanner(Scanner):
    def perform(self, launch_properties, scan_properties):
        self.session.get('http://testscan')


class MockResponse:
    status_code = 200

    text = 'coucou'

    def json(self):
        return {'response_types_supported': ['code'],
                'authorization_endpoint': 'http://testscan/auth',
                'response_modes_supported': ['form_post']
                }

@fixture
def well_known():
    return MockResponse()


def test_start():

    session = requests.Session()
    session.get = MagicMock()
    scanner = MasterScanner({
        'base_url': 'http://localhost',
        'realms': ['test-realm'],
        'clients': ['test-client'],
        'username': 'username',
        'password': 'password'
    }, session, {TestScanner()})
    scanner.start()

    assert scanner.session == session
    session.get.assert_called_with('http://testscan')

def test_full_scan(well_known):

    SCANS = [
        RealmScanner(),
        WellKnownScanner(),
        ClientScanner(),
        SecurityConsoleScanner(),
        OpenRedirectScanner(),
        FormPostXssScanner(),
        NoneSignScanner()
    ]

    session = requests.Session()
    session.get = MagicMock(return_value=well_known)
    session.post = MagicMock()
    session.put = MagicMock()
    session.delete = MagicMock()

    scanner = MasterScanner({
        'base_url': 'http://testscan',
        'realms': ['realm1'],
        'clients': ['client1', 'client2'],
        'username': 'username1',
        'password': 'password123'
    }, session=session, scans=SCANS)
    scanner.start()
