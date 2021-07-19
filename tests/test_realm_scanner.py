from requests import Session

from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scan_base.types import Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm):

    scanner = RealmScanner(base_url=base_url, realms=['master', 'other'],
                           session_provider=lambda: full_scan_mock_session)

    mediator = Mediator([scanner])

    scanner.perform_base()

    assert mediator.scan_results.get(WrapperTypes.REALM_TYPE) == {master_realm, other_realm}

    # TODO: vuln flag ?
    #assert not vf.has_vuln