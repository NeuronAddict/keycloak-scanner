from requests import Session

from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnown


def test_perform(master_realm: Realm, full_scan_mock_session: Session, well_known_json: dict):

    scanner = WellKnownScanner(base_url='http://testscan', session=full_scan_mock_session)

    result = scanner.perform([master_realm])

    assert result == {
        'master': WellKnown(master_realm, name='master', url='http://testscan/auth/realms/master/.well-known/openid-configuration', json=well_known_json)
    }
