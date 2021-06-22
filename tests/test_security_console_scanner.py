from requests import Session

from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.types import Realm
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(master_realm: Realm, base_url: str, full_scan_mock_session: Session):

    mediator = Mediator([
        SecurityConsoleScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)
    ])

    mediator.send(WrapperTypes.REALM_TYPE, {master_realm})

    assert mediator.scan_results.get(WrapperTypes.SECURITY_CONSOLE) == set()

    # TODO: test when a vuln is find
