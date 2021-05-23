from requests import Session

from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm


def test_perform(full_scan_mock_session: Session, master_realm: dict, other_realm: dict):

    scanner = RealmScanner(base_url='http://testscan', realms=['master', 'other'], session=full_scan_mock_session)

    result = scanner.perform()

    assert result == [
        Realm('master', 'http://testscan/auth/realms/master', master_realm),
        Realm('other', 'http://testscan/auth/realms/other', other_realm)
    ]
