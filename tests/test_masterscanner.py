from unittest.mock import MagicMock

import requests
from requests import Session

from keycloak_scanner.masterscanner import MasterScanner, to_camel_case
from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.login_scanner import LoginScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from tests.mock_response import MockResponse


def test_start(base_url: str, full_scan_mock_session: Session):

    common_args = {
        'base_url': base_url,
        'session_provider': lambda: full_scan_mock_session
    }

    ms = MasterScanner(scans=[
        RealmScanner(**common_args, realms=['master', 'other']),
        WellKnownScanner(**common_args),
        ClientScanner(**common_args, clients=['client1', 'client2']),
        LoginScanner(**common_args, username='admin', password='admin'),
        SecurityConsoleScanner(**common_args),
        OpenRedirectScanner(**common_args),
        FormPostXssScanner(**common_args),
        NoneSignScanner(**common_args)
    ])

    status = ms.start()

    assert not status.has_error
    assert status.has_vulns


def test_start_open_redirect(well_known_dict):

    session = requests.Session()
    session.get = MagicMock(return_value=MockResponse(status_code=200, response={}))

    open_redirect_scanner = OpenRedirectScanner(base_url='http://localhost', session_provider=lambda: session)

    ms = MasterScanner(scans=[open_redirect_scanner], previous_deps={
        'realms': ['master'],
        'clients': ['client1'],
        'well_known_dic': well_known_dict
    })

    ms.start()


def test_camel_case():
    assert to_camel_case('ClassName') == 'class_name'
    assert to_camel_case('WellKnown') == 'well_known'
    assert to_camel_case('Realms') == 'realms'
