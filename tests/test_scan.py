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
    def perform(self, scan_properties):
        super().session().get(super().base_url())


def test_start():
    session = requests.Session()
    session.get = MagicMock()
    scanner = MasterScanner([TestScanner(base_url='http://testscan', session=session)])
    scanner.start()
    session.get.assert_called_with('http://testscan')


def test_full_scan(full_scan_mock_session):

    scans = [
        RealmScanner(base_url='http://testscan', session=full_scan_mock_session, realms=['master', 'other']),
        WellKnownScanner(base_url='http://testscan', session=full_scan_mock_session),
        ClientScanner(base_url='http://testscan', session=full_scan_mock_session, clients=['client1', 'client2']),
        SecurityConsoleScanner(base_url='http://testscan', session=full_scan_mock_session),
        OpenRedirectScanner(base_url='http://testscan', session=full_scan_mock_session),
        FormPostXssScanner(base_url='http://testscan', session=full_scan_mock_session),
        NoneSignScanner(base_url='http://testscan', session=full_scan_mock_session)
    ]

    scanner = MasterScanner(scans=scans)
    scanner.start()

    assert scanner.scan_properties == {'clients': {'master': ['client1', 'client2'], 'other': ['client1', 'client2']},
                                       'realms': {'master': {'authorization_endpoint': 'http://testscan/auth',
                                                             'response_modes_supported': ['form_post'],
                                                             'response_types_supported': ['code']},
                                                  'other': {'authorization_endpoint': 'http://testscan/auth',
                                                            'response_modes_supported': ['form_post'],
                                                            'response_types_supported': ['code']}},
                                       'wellknowns': {'master': {'authorization_endpoint': 'http://testscan/auth',
                                                                 'response_modes_supported': ['form_post'],
                                                                 'response_types_supported': ['code']},
                                                      'other': {'authorization_endpoint': 'http://testscan/auth',
                                                                'response_modes_supported': ['form_post'],
                                                                'response_types_supported': ['code']}}}
