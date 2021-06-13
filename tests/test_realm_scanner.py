from requests import Session

from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.types import Realm, realmType


def test_perform_with_event(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm):

    mediator = Mediator()

    scanner = RealmScanner(mediator=mediator, result_type=realmType, base_url=base_url, realms=['master', 'other'],
                           session_provider=lambda: full_scan_mock_session)

    scanner.perform_base()

    assert mediator.scan_results.get(realmType) == [master_realm, other_realm]

    # TODO: vuln flag ?
    #assert not vf.has_vuln