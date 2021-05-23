from requests import Session

from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


def test_perform(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm,
                 client1: Client, client2: Client, well_known_dict: WellKnownDict):

    open_redirect_scanner = OpenRedirectScanner(base_url=base_url, session=full_scan_mock_session)

    result = open_redirect_scanner.perform(realms=[master_realm, other_realm], clients=[client1, client1],
                                           well_known_dict=well_known_dict)

    assert result.results == {'master-client1': True, 'other-client1': True}
