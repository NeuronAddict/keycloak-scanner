from typing import List

from requests import Session

from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.types import Realm, WellKnown, realmType, wellKnownType
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner


def test_perform_with_event(base_url: str, all_realms: List[Realm],
                            full_scan_mock_session: Session,
                            well_known_list: List[WellKnown]):

    mediator = Mediator()

    realms_scanner = RealmScanner(mediator=mediator, realms=['master', 'other'], base_url=base_url, session_provider=lambda: full_scan_mock_session)

    well_known_scanner = WellKnownScanner(mediator=mediator, base_url=base_url, session_provider=lambda: full_scan_mock_session)

    realms_scanner.perform_base()

    assert mediator.scan_results.get(realmType) == all_realms
    assert mediator.scan_results.get(wellKnownType) == well_known_list
