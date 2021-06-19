from unittest.mock import MagicMock

import pytest
import requests
from _pytest.capture import CaptureFixture
from requests import Session

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.login_scanner import LoginScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from keycloak_scanner.scanners.wrap import WrapperType
from tests.mock_response import MockResponse, MockSpec, RequestSpec


def test_start(base_url: str, full_scan_mock_session: Session, capsys: CaptureFixture):

    common_args = {
        'base_url': base_url,
        'session_provider': lambda: full_scan_mock_session
    }

    ms = MasterScanner(scanners=[
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

    #assert captured.err == '[WARN] Result of SecurityConsoleScanner as no results (void list), subsequent scans can be void too.\n'

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "[INFO] Find a well known for realm master" in captured.out

    assert "[INFO] Find a client for realm master: client1" in captured.out

    assert "[INFO] Find a client for realm master: client2" in captured.out

    assert "[INFO] Find a client for realm other: client1" in captured.out

    assert "[INFO] Find a client for realm other: client2" in captured.out

    # TODO : all login work in mock
    assert "[+] LoginScanner - Form login work for admin on realm other, client client1, (<openid location>)" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm other, client client2, grant_type: password" in captured.out

    assert not status.has_error
    assert status.has_vulns


def test_should_fail_fast(base_url: str, full_scan_mock: MockSpec, capsys: CaptureFixture):

    common_args = {
        'base_url': base_url,
        'session_provider': lambda: full_scan_mock.session()
    }

    class FailFastException(Exception):
        pass

    class ErrorScanner(Scanner[str]):

        def __init__(self, **kwargs):
            super().__init__(result_type=WrapperType(str), **kwargs)

        def perform(self, **kwargs) -> (str, VulnFlag):
            raise FailFastException()

    ms = MasterScanner(scanners=[
        RealmScanner(**common_args, realms=['master', 'other']),
        WellKnownScanner(**common_args),
        ErrorScanner(**common_args),
        ClientScanner(**common_args, clients=['client1', 'client2']),
        LoginScanner(**common_args, username='admin', password='admin'),
        SecurityConsoleScanner(**common_args),
        OpenRedirectScanner(**common_args),
        FormPostXssScanner(**common_args),
        NoneSignScanner(**common_args)
    ], fail_fast=True)

    with pytest.raises(FailFastException) as e:

        status = ms.start()

        assert status.has_error is True

        # TODO when vf was fixed
        # assert status.has_vulns is True

    captured = capsys.readouterr()

    print(captured.out)

    assert captured.err == ''

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "[INFO] Find a well known for realm master" in captured.out
