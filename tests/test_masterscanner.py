from unittest.mock import MagicMock

import requests
from _pytest.capture import CaptureFixture
from requests import Session

from keycloak_scanner.masterscanner import MasterScanner, to_camel_case
from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client, Clients
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.login_scanner import LoginScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm, Realms
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from tests.mock_response import MockResponse, MockSpec, RequestSpec


def test_start(base_url: str, full_scan_mock_session: Session, capsys: CaptureFixture):

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

    captured = capsys.readouterr()

    print(captured.out)

    assert captured.err == '[WARN] Result of SecurityConsoleScanner as no results (void list), subsequent scans can be void too.\n'

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "[INFO] Find a well known for realm Realm('master'" in captured.out

    assert "[INFO] Find a client for realm master: client1" in captured.out

    assert "[INFO] Find a client for realm master: client2" in captured.out

    assert "[INFO] Find a client for realm other: client1" in captured.out

    assert "[INFO] Find a client for realm other: client2" in captured.out

    # TODO : all login work in mock
    assert "[+] LoginScanner - Form login work for admin on realm other, client client1, (<openid location>)" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm other, client client2, grant_type: password" in captured.out

    assert not status.has_error
    assert status.has_vulns


def test_start_open_redirect(well_known_dict, master_realm: Realm, client1: Client, capsys):

    params = {
        'response_type': 'code',
        'client_id': 'client1',
        'redirect_uri': f'https://devops-devsecops.org/auth/master/client1/'
    }
    session_provider = lambda: MockSpec(get={
        'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth':
            RequestSpec(response=MockResponse(status_code=200),
                        assertion=lambda **kwargs: kwargs['params'] == params, assertion_value=params)
    }).session()

    open_redirect_scanner = OpenRedirectScanner(base_url='http://localhost', session_provider=session_provider)

    ms = MasterScanner(scans=[open_redirect_scanner], previous_deps={
        'realms': Realms([master_realm]),
        'clients': Clients([client1]),
        'well_known_dict': well_known_dict
    })

    status = ms.start()

    captured = capsys.readouterr()
    print(captured.out)


    assert captured.err == ''
    assert '[INFO] Start scanner OpenRedirectScanner...' in captured.out

    assert '[+] OpenRedirection - Open redirection for realm master and clientid client1' in captured.out

    assert not status.has_error
    assert status.has_vulns


def test_camel_case():
    assert to_camel_case('ClassName') == 'class_name'
    assert to_camel_case('WellKnown') == 'well_known'
    assert to_camel_case('Realms') == 'realms'

def test_should_fail_fast():
    pass
