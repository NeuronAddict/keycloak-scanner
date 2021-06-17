from requests import Session

from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner


def test_perform(master_realm: Realm, base_url: str, full_scan_mock_session: Session):

    scanner = SecurityConsoleScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)
    result, vf = scanner.perform(master_realm)

    assert result == []

    assert not vf.has_vuln

    # TODO: test when a vuln is find
