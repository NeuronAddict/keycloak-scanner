from requests import Session

from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm


def test_perform(base_url: str, full_scan_mock_session: Session, master_realm: Realm, other_realm: Realm):

    scanner = RealmScanner(base_url=base_url, realms=['master', 'other'], session=full_scan_mock_session)

    result, vf = scanner.perform()

    assert result == [master_realm, other_realm]

    assert not vf.has_vuln