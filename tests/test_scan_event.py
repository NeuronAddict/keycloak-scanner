from typing import List

from requests import Session

from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scan_base.types import Realm, WellKnown
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url: str, all_realms: List[Realm],
                            full_scan_mock_session: Session,
                            well_known_list: List[WellKnown]):

    realms_scanner = RealmScanner(realms=['master', 'other'], base_url=base_url,
                                  session_provider=lambda: full_scan_mock_session)

    well_known_scanner = WellKnownScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)

    client_scanner = ClientScanner(clients=['client1', 'client2'], base_url=base_url,
                                   session_provider=lambda: full_scan_mock_session)

    mediator = Mediator([
        realms_scanner,
        well_known_scanner,
        client_scanner
    ])

    mediator.start()

    assert mediator.scan_results.get(WrapperTypes.REALM_TYPE) == set(all_realms)
    assert mediator.scan_results.get(WrapperTypes.WELL_KNOWN_TYPE) == set(well_known_list)
    assert len(mediator.scan_results.get(WrapperTypes.CLIENT_TYPE)) == 4
