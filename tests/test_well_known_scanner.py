from requests import Session

from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnown


def test_perform(full_scan_mock_session: Session, master_realm: dict, well_known: dict):
    scanner = WellKnownScanner(base_url='http://testscan', session=full_scan_mock_session)

    # todo : add on conftest
    master_realm = Realm('master', 'http://testscan/auth/master', master_realm)

    result = scanner.perform([master_realm])

    assert result == [
        WellKnown(master_realm, name='master', url='http://testscan/auth/realms/master/.well-known/openid-configuration', json=well_known)
    ]