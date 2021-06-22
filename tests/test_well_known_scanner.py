from typing import List

from requests import Session

from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.types import WellKnown, Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url: str, all_realms: List[Realm],
                            full_scan_mock_session: Session,
                            well_known_list: List[WellKnown]):

    mediator = Mediator([
        WellKnownScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)
    ])

    mediator.send(WrapperTypes.REALM_TYPE, set(all_realms))

    assert mediator.scan_results.get(WrapperTypes.WELL_KNOWN_TYPE) == set(well_known_list)


    # TODO : keep vf ?
    #assert not vf.has_vuln
