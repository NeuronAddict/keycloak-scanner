from unittest.mock import MagicMock

import requests

from keycloak_scanner.clients_scanner import ClientScan
from keycloak_scanner.form_post_xss_scan import FormPostXssScan
from keycloak_scanner.none_sign_scan import NoneSignScan
from keycloak_scanner.open_redirect_scanner import OpenRedirectScan
from keycloak_scanner.realm_scanner import RealmScanner

from keycloak_scanner.scan import Scan
from keycloak_scanner.scanner import Scanner
from keycloak_scanner.security_console_scanner import SecurityConsoleScan
from keycloak_scanner.well_known_scanner import WellKnownScan


class TestScan(Scan):
    def perform(self, launch_properties, scan_properties):
        self.session.get('http://testscan')


def test_start():

    session = requests.Session()
    session.get = MagicMock()
    scanner = Scanner({
        'base_url': 'http://localhost',
        'realms': ['test-realm'],
        'clients': ['test-client'],
        'username': 'username',
        'password': 'password'
    }, session, {TestScan()})
    scanner.start()

    assert scanner.session == session
    session.get.assert_called_with('http://testscan')


def test_full_scan():

    SCANS = [
        RealmScanner(),
        WellKnownScan(),
        ClientScan(),
        SecurityConsoleScan(),
        OpenRedirectScan(),
        FormPostXssScan(),
        NoneSignScan()
    ]

    session = requests.Session()
    session.get = MagicMock()
    session.post = MagicMock()
    session.put = MagicMock()
    session.delete = MagicMock()

    scanner = Scanner({
        'base_url': 'http://testscan',
        'realms': ['realm1'],
        'clients': ['client1', 'client2'],
        'username': 'username1',
        'password': 'password123'
    }, session=session, scans=SCANS)
    scanner.start()
