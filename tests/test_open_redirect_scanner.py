from typing import List

from requests import Session

from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scan_base.types import WellKnown, OpenRedirect, Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm,
                            client1: Client, client2: Client, well_known_list: List[WellKnown]):
    mediator = Mediator(
        [
            OpenRedirectScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)
        ]
    )

    mediator.send(WrapperTypes.REALM_TYPE, {master_realm, other_realm})
    mediator.send(WrapperTypes.CLIENT_TYPE, {client1})
    mediator.send(WrapperTypes.WELL_KNOWN_TYPE, set(well_known_list))

    assert mediator.scan_results.get(WrapperTypes.OPEN_REDIRECT) == {
        OpenRedirect(master_realm, client1), OpenRedirect(other_realm, client1),
    }
