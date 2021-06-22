from typing import List

from requests import Session

from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.types import Client, WellKnown, Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url, full_scan_mock_session: Session, all_realms: List[Realm], all_clients: List[Client],
                 well_known_list: List[WellKnown], master_realm: Realm, other_realm: Realm):

    scanner = FormPostXssScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)

    mediator = Mediator([scanner])

    mediator.send(WrapperTypes.REALM_TYPE, set(all_realms))
    mediator.send(WrapperTypes.CLIENT_TYPE, set(all_clients))
    mediator.send(WrapperTypes.WELL_KNOWN_TYPE, set(well_known_list))

    assert mediator.scan_results.get(WrapperTypes.FORM_POST_XSS) == set()


## TODO: test when vulnerable