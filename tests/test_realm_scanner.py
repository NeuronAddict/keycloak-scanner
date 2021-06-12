from requests import Session

from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.types import Realm, RealmType


def test_perform(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm):

    mediator = Mediator()

    scanner = RealmScanner(mediator=mediator, result_type=RealmType, base_url=base_url, realms=['master', 'other'],
                           session_provider=lambda: full_scan_mock_session)

    result, vf = scanner.perform()

    assert result == [master_realm, other_realm]

    assert not vf.has_vuln