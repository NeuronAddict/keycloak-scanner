from requests import Session

from keycloak_scanner.scanners.realm_scanner import Realms
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnownDict


def test_perform(base_url: str, all_realms: Realms, full_scan_mock_session: Session, well_known_dict: WellKnownDict):

    scanner = WellKnownScanner(base_url=base_url, session=full_scan_mock_session)

    result, vf = scanner.perform(all_realms)

    assert result == well_known_dict

    assert well_known_dict['master'].allowed_grants() == ['authorization_code',
                                                          'implicit',
                                                          'refresh_token',
                                                          'password',
                                                          'client_credentials',
                                                          'urn:ietf:params:oauth:grant-type:device_code',
                                                          'urn:openid:params:grant-type:ciba']

    assert not vf.has_vuln
