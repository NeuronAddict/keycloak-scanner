from requests import Session

from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm


def test_perform(full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm):

    scanner = RealmScanner(base_url='http://testscan', realms=['master', 'other'], session=full_scan_mock_session)

    result = scanner.perform()

    assert result == [master_realm, other_realm]
