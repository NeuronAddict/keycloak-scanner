import requests

from keycloak_scanner.scanners.clients_scanner import Clients, Client
from keycloak_scanner.scanners.login_scanner import LoginScanner, Credential
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


def test_perform(base_url: str, all_realms: Realms, all_clients: Clients, well_known_dict: WellKnownDict,
                 full_scan_mock_session: requests.Session, capsys):

    captured = capsys.readouterr()

    scanner = LoginScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session, username='admin',
                           password='pa55w0rd')

    result, vf = scanner.perform(realms=all_realms, clients=all_clients, well_known_dict=well_known_dict)

    assert result == {'master-client1': Credential(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), Client('client1', 'http://localhost:8080/auth/realms/master/client1', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'), 'admin', 'pa55w0rd'),
 'master-client2': Credential(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), Client('client2', 'http://localhost:8080/auth/realms/master/client2', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'), 'admin', 'pa55w0rd'),
 'other-client1': Credential(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0}), Client('client1', 'http://localhost:8080/auth/realms/master/client1', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'), 'admin', 'pa55w0rd'),
 'other-client2': Credential(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0}), Client('client2', 'http://localhost:8080/auth/realms/master/client2', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'), 'admin', 'pa55w0rd')}

    assert not vf.has_vuln

    assert "[+] LoginScanner - Form login work for admin on realm other, client client2, (<openid location>)" in captured.out
