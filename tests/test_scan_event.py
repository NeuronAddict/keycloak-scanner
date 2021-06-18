from typing import List

from requests import Session

from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scanners.types import Realm, WellKnown, realmType, wellKnownType, clientType, Client, ClientConfig
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from tests.mock_response import MockSpec, RequestSpec, MockResponse


def test_perform_with_event(base_url: str, all_realms: List[Realm],
                            full_scan_mock_session: Session,
                            well_known_list: List[WellKnown]):
    mediator = Mediator()

    realms_scanner = RealmScanner(realms=['master', 'other'], base_url=base_url,
                                  session_provider=lambda: full_scan_mock_session)

    well_known_scanner = WellKnownScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)

    client_scanner = ClientScanner(clients=['client1', 'client2'], base_url=base_url,
                                   session_provider=lambda: full_scan_mock_session)

    mediator.add(realms_scanner)
    mediator.add(well_known_scanner)
    mediator.add(client_scanner)

    realms_scanner.perform_base()

    assert mediator.scan_results.get(realmType) == all_realms
    assert mediator.scan_results.get(wellKnownType) == well_known_list
    assert len(mediator.scan_results.get(clientType)) == 4
