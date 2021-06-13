from typing import List

from requests import Session

from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import Realms
from keycloak_scanner.scanners.types import RealmType, WellKnown, wellKnownType
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner


def test_perform_with_event(base_url: str, all_realms: Realms,
                            full_scan_mock_session: Session,
                            well_known_list: List[WellKnown]):

    mediator = Mediator()

    scanner = WellKnownScanner(mediator=mediator, base_url=base_url, session_provider=lambda: full_scan_mock_session)

    for realm in all_realms:
        scanner.receive(RealmType, realm)

    # TODO : remove list type
    assert mediator.scan_results.get(wellKnownType) == well_known_list


    # TODO : keep vf ?
    #assert not vf.has_vuln
