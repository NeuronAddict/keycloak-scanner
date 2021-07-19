from typing import List
from unittest.mock import MagicMock

import requests

from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.login_scanner import LoginScanner, Credential
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.session_holder import SessionProvider
from keycloak_scanner.scan_base.types import WellKnown, Realm, Username, Password
from keycloak_scanner.scan_base.wrap import WrapperTypes


def test_perform_with_event(base_url: str, all_realms: List[Realm], all_clients: List[Client],
                            well_known_list: List[WellKnown],
                            full_scan_mock_session: requests.Session, capsys):
    mediator = Mediator([
        LoginScanner(base_url=base_url, session_provider=lambda: full_scan_mock_session)
    ])

    mediator.send(WrapperTypes.USERNAME_TYPE, {Username('admin')})
    mediator.send(WrapperTypes.PASSWORD_TYPE, {Password('pa55w0rd')})

    mediator.send(WrapperTypes.REALM_TYPE, set(all_realms))
    mediator.send(WrapperTypes.CLIENT_TYPE, set(all_clients))
    mediator.send(WrapperTypes.WELL_KNOWN_TYPE, set(well_known_list))

    result = mediator.scan_results.get(WrapperTypes.CREDENTIAL_TYPE)

    captured = capsys.readouterr()

    assert result == {Credential(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master',
                                                                                              'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                              'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                                              'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                                              'tokens-not-before': 0}),
                                 Client('client1', 'http://localhost:8080/auth/realms/master/client1'), 'admin',
                                 'pa55w0rd'),
                      Credential(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master',
                                                                                              'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                              'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                                              'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                                              'tokens-not-before': 0}),
                                 Client('client2', 'http://localhost:8080/auth/realms/master/client2'), 'admin',
                                 'pa55w0rd'),
                      Credential(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other',
                                                                                            'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                            'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                            'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                            'tokens-not-before': 0}),
                                 Client('client1', 'http://localhost:8080/auth/realms/master/client1'), 'admin',
                                 'pa55w0rd'),
                      Credential(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other',
                                                                                            'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                            'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                            'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                            'tokens-not-before': 0}),
                                 Client('client2', 'http://localhost:8080/auth/realms/master/client2'), 'admin',
                                 'pa55w0rd')}

    assert "[+] LoginScanner - Form login work for admin on realm other, client client2, (<openid location>)" in captured.out


def test_get_token(master_realm: Realm, client1: Client, well_known_list: List[WellKnown]):
    session = requests.session()
    session.post = MagicMock()

    def get_mock_session() -> requests.Session:
        return session

    credential = Credential(master_realm, client1, username='admin', password='pa55w0rd')

    session_provider: SessionProvider = get_mock_session

    credential.get_token(session_provider, well_known_list[0])

    session.post.assert_called_once_with('http://localhost:8080/auth/realms/master/protocol/openid-connect/token',
                                         data={
                                             'client_id': 'client1',
                                             'username': 'admin',
                                             'password': 'pa55w0rd',
                                             'grant_type': 'password',
                                             'client_secret': ''
                                         }
                                         )
