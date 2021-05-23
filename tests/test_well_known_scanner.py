from requests import Session

from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnown, WellKnownDict


def test_perform(base_url: str, master_realm: Realm, other_realm: Realm, full_scan_mock_session: Session, well_known_dict: WellKnownDict):

    scanner = WellKnownScanner(base_url=base_url, session=full_scan_mock_session)

    result = scanner.perform([master_realm, other_realm])

    assert result == well_known_dict
