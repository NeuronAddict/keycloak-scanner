from unittest.mock import MagicMock

import requests
from requests import Session

from keycloak_scanner.masterscanner import MasterScanner, to_camel_case
from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner, Realms, Clients, WellKnown
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from tests.mock_response import MockResponse


def test_start(well_known: dict, full_scan_mock_session: Session):

    session = requests.Session()
    session.get = MagicMock(return_value=MockResponse(status_code=200, response={}))

    base_url = 'http://localhost'

    ms = MasterScanner(scans=[
        RealmScanner(base_url=base_url, session=session, realms=['master', 'other']),
        WellKnownScanner(base_url=base_url, session=session),
        ClientScanner(base_url=base_url, session=session, clients=['client1', 'client2']),
        SecurityConsoleScanner(base_url=base_url, session=session),
        OpenRedirectScanner(base_url=base_url, session=session),
        FormPostXssScanner(base_url=base_url, session=session),
        NoneSignScanner(base_url=base_url, session=session)
    ])

    ms.start()


def test_start_open_redirect(well_known: dict):

    session = requests.Session()
    session.get = MagicMock(return_value=MockResponse(status_code=200, response={}))

    open_redirect_scanner = OpenRedirectScanner(base_url='http://localhost', session=session)

    ms = MasterScanner(scans=[open_redirect_scanner], previous_deps={
        'realms': ['master'],
        'clients': ['client1'],
        'wellKnown': WellKnown(well_known)
    })

    ms.start()

def test_camel_case():
    assert to_camel_case('ClassName') == 'class_name'
    assert to_camel_case('WellKnown') == 'well_known'
    assert to_camel_case('Realms') == 'realms'
