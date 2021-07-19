import uuid
from typing import List

from requests import Session

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.clientregistration_scanner import ClientRegistrationScanner, ClientRegistration
from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client, ClientConfig
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.login_scanner import LoginScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner, OpenRedirect
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scan_base.types import Credential, Realm, Username, Password
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnown
from keycloak_scanner.scan_base.wrap import WrapperTypes
from tests.mock_response import MockPrintLogger


class TestResult:
    pass


class TestResultList(List[str], MockPrintLogger):
    __test__ = False


class TestScanner(Scanner[TestResult], MockPrintLogger):
    __test__ = False

    def perform(self):
        super().session().get(super().base_url())
        return TestResult()


class TestScannerList(Scanner[TestResultList], MockPrintLogger):
    __test__ = False

    def perform(self):
        super().session().get(super().base_url())
        return TestResultList(), VulnFlag(True)


class TestMasterScanner(MasterScanner, MockPrintLogger):
    __test__ = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


def test_full_scan(base_url: str, full_scan_mock_session: Session, monkeypatch,
                   master_realm: Realm, other_realm: Realm,
                   client1: Client, client2: Client,
                   well_known_master: WellKnown,
                   well_known_other: WellKnown
                   ):
    monkeypatch.setattr(uuid, 'uuid4', value=lambda: '456789')

    common_args = {
        'base_url': base_url,
        'session_provider': lambda: full_scan_mock_session
    }

    scanners = [
        RealmScanner(realms=['master', 'other'], **common_args),
        WellKnownScanner(**common_args),
        ClientScanner(clients=['client1', 'client2'], **common_args),
        LoginScanner(**common_args),
        ClientRegistrationScanner(**common_args, callback_url=['http://callback']),
        SecurityConsoleScanner(**common_args),
        OpenRedirectScanner(**common_args),
        FormPostXssScanner(**common_args),
        NoneSignScanner(**common_args)
    ]

    scanner = MasterScanner(scanners=scanners, initial_values={
        WrapperTypes.USERNAME_TYPE: {Username('user')}, WrapperTypes.PASSWORD_TYPE: {Password('user')}
    }, verbose=True)
    scanner.start()

    assert scanner.mediator.scan_results.get(WrapperTypes.CLIENT_REGISTRATION) == {
        ClientRegistration('http://callback', name='keycloak-client-456789',
                           url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
                           json={'redirect_uris': ['http://localhost:8080/callback'],
                                 'token_endpoint_auth_method': 'client_secret_basic',
                                 'grant_types': ['authorization_code', 'refresh_token'],
                                 'response_types': ['code', 'none'],
                                 'client_id': '539ce782-5d15-4256-a5fa-1a46609d056b',
                                 'client_secret': 'c94f5fc0-0a04-4e2f-aec6-b1f5edad1d44',
                                 'client_name': 'keycloak-client-456789',
                                 'scope': 'address phone offline_access microprofile-jwt',
                                 'jwks_uri': 'http://localhost:8080/public_keys.jwks',
                                 'subject_type': 'pairwise',
                                 'request_uris': ['http://localhost:8080/rf.txt'],
                                 'tls_client_certificate_bound_access_tokens': False,
                                 'client_id_issued_at': 1622306364, 'client_secret_expires_at': 0,
                                 'registration_client_uri': 'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
                                 'backchannel_logout_session_required': False}),
        ClientRegistration('http://callback', name='keycloak-client-456789',
                           url='http://localhost:8080/auth/realms/other/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
                           json={'redirect_uris': ['http://localhost:8080/callback'],
                                 'token_endpoint_auth_method': 'client_secret_basic',
                                 'grant_types': ['authorization_code', 'refresh_token'],
                                 'response_types': ['code', 'none'],
                                 'client_id': '539ce782-5d15-4256-a5fa-1a46609d056b',
                                 'client_secret': 'c94f5fc0-0a04-4e2f-aec6-b1f5edad1d44',
                                 'client_name': 'keycloak-client-456789',
                                 'scope': 'address phone offline_access microprofile-jwt',
                                 'jwks_uri': 'http://localhost:8080/public_keys.jwks',
                                 'subject_type': 'pairwise',
                                 'request_uris': ['http://localhost:8080/rf.txt'],
                                 'tls_client_certificate_bound_access_tokens': False,
                                 'client_id_issued_at': 1622306364, 'client_secret_expires_at': 0,
                                 'registration_client_uri': 'http://localhost:8080/auth/realms/other/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
                                 'backchannel_logout_session_required': False})}

    assert scanner.mediator.scan_results.get(WrapperTypes.CLIENT_TYPE) == {
        Client('client1', 'http://localhost:8080/auth/realms/master/client1',
               ClientConfig('client1',
                            'http://localhost:8080/realms/master/clients-registrations/default/client1',
                            {'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313', 'clientId': 'admin-cli',
                             'name': '${client_admin-cli}', 'surrogateAuthRequired': False,
                             'enabled': True, 'alwaysDisplayInConsole': False,
                             'clientAuthenticatorType': 'client-secret', 'redirectUris': [],
                             'webOrigins': [], 'notBefore': 0, 'bearerOnly': False,
                             'consentRequired': False, 'standardFlowEnabled': False,
                             'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False,
                             'serviceAccountsEnabled': False, 'publicClient': False,
                             'frontchannelLogout': False, 'protocol': 'openid-connect',
                             'attributes': {}, 'authenticationFlowBindingOverrides': {},
                             'fullScopeAllowed': False, 'nodeReRegistrationTimeout': 0,
                             'defaultClientScopes': ['web-origins', 'roles', 'profile', 'email'],
                             'optionalClientScopes': ['address', 'phone', 'offline_access',
                                                      'microprofile-jwt']})),
        Client('client2', 'http://localhost:8080/auth/realms/master/client2', None),
        Client('client1', 'http://localhost:8080/auth/realms/other/client1',
               ClientConfig('client1',
                            'http://localhost:8080/realms/other/clients-registrations/default/client1',
                            {'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313', 'clientId': 'admin-cli',
                             'name': '${client_admin-cli}', 'surrogateAuthRequired': False,
                             'enabled': True, 'alwaysDisplayInConsole': False,
                             'clientAuthenticatorType': 'client-secret', 'redirectUris': [],
                             'webOrigins': [], 'notBefore': 0, 'bearerOnly': False,
                             'consentRequired': False, 'standardFlowEnabled': False,
                             'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False,
                             'serviceAccountsEnabled': False, 'publicClient': False,
                             'frontchannelLogout': False, 'protocol': 'openid-connect',
                             'attributes': {}, 'authenticationFlowBindingOverrides': {},
                             'fullScopeAllowed': False, 'nodeReRegistrationTimeout': 0,
                             'defaultClientScopes': ['web-origins', 'roles', 'profile', 'email'],
                             'optionalClientScopes': ['address', 'phone', 'offline_access',
                                                      'microprofile-jwt']})),
        Client('client2', 'http://localhost:8080/auth/realms/other/client2', None)}

    for r in scanner.mediator.scan_results.get(WrapperTypes.CREDENTIAL_TYPE):
        print('####')
        print(repr(r))
        print(hash(r))
        print('####')

    assert scanner.mediator.scan_results.get(WrapperTypes.CREDENTIAL_TYPE) == {Credential(
        Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master',
                                                                     'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                     'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                     'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                     'tokens-not-before': 0}),
        Client('client2', 'http://localhost:8080/auth/realms/other/client2', None), 'user', 'user'),
                                                                               Credential(Realm('master',
                                                                                                'http://localhost:8080/auth/realms/master',
                                                                                                {'realm': 'master',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client2',
                                                                                                 'http://localhost:8080/auth/realms/master/client2',
                                                                                                 None), 'user', 'user'),
                                                                               Credential(Realm('master',
                                                                                                'http://localhost:8080/auth/realms/master',
                                                                                                {'realm': 'master',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client1',
                                                                                                 'http://localhost:8080/auth/realms/master/client1',
                                                                                                 ClientConfig('client1',
                                                                                                              'http://localhost:8080/realms/master/clients-registrations/default/client1',
                                                                                                              {
                                                                                                                  'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313',
                                                                                                                  'clientId': 'admin-cli',
                                                                                                                  'name': '${client_admin-cli}',
                                                                                                                  'surrogateAuthRequired': False,
                                                                                                                  'enabled': True,
                                                                                                                  'alwaysDisplayInConsole': False,
                                                                                                                  'clientAuthenticatorType': 'client-secret',
                                                                                                                  'redirectUris': [],
                                                                                                                  'webOrigins': [],
                                                                                                                  'notBefore': 0,
                                                                                                                  'bearerOnly': False,
                                                                                                                  'consentRequired': False,
                                                                                                                  'standardFlowEnabled': False,
                                                                                                                  'implicitFlowEnabled': False,
                                                                                                                  'directAccessGrantsEnabled': False,
                                                                                                                  'serviceAccountsEnabled': False,
                                                                                                                  'publicClient': False,
                                                                                                                  'frontchannelLogout': False,
                                                                                                                  'protocol': 'openid-connect',
                                                                                                                  'attributes': {},
                                                                                                                  'authenticationFlowBindingOverrides': {},
                                                                                                                  'fullScopeAllowed': False,
                                                                                                                  'nodeReRegistrationTimeout': 0,
                                                                                                                  'defaultClientScopes': [
                                                                                                                      'web-origins',
                                                                                                                      'roles',
                                                                                                                      'profile',
                                                                                                                      'email'],
                                                                                                                  'optionalClientScopes': [
                                                                                                                      'address',
                                                                                                                      'phone',
                                                                                                                      'offline_access',
                                                                                                                      'microprofile-jwt']})),
                                                                                          'user', 'user'),
                                                                               Credential(Realm('other',
                                                                                                'http://localhost:8080/auth/realms/other',
                                                                                                {'realm': 'other',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client2',
                                                                                                 'http://localhost:8080/auth/realms/master/client2',
                                                                                                 None), 'user', 'user'),
                                                                               Credential(Realm('other',
                                                                                                'http://localhost:8080/auth/realms/other',
                                                                                                {'realm': 'other',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client2',
                                                                                                 'http://localhost:8080/auth/realms/other/client2',
                                                                                                 None), 'user', 'user'),
                                                                               Credential(Realm('other',
                                                                                                'http://localhost:8080/auth/realms/other',
                                                                                                {'realm': 'other',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client1',
                                                                                                 'http://localhost:8080/auth/realms/master/client1',
                                                                                                 ClientConfig('client1',
                                                                                                              'http://localhost:8080/realms/master/clients-registrations/default/client1',
                                                                                                              {
                                                                                                                  'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313',
                                                                                                                  'clientId': 'admin-cli',
                                                                                                                  'name': '${client_admin-cli}',
                                                                                                                  'surrogateAuthRequired': False,
                                                                                                                  'enabled': True,
                                                                                                                  'alwaysDisplayInConsole': False,
                                                                                                                  'clientAuthenticatorType': 'client-secret',
                                                                                                                  'redirectUris': [],
                                                                                                                  'webOrigins': [],
                                                                                                                  'notBefore': 0,
                                                                                                                  'bearerOnly': False,
                                                                                                                  'consentRequired': False,
                                                                                                                  'standardFlowEnabled': False,
                                                                                                                  'implicitFlowEnabled': False,
                                                                                                                  'directAccessGrantsEnabled': False,
                                                                                                                  'serviceAccountsEnabled': False,
                                                                                                                  'publicClient': False,
                                                                                                                  'frontchannelLogout': False,
                                                                                                                  'protocol': 'openid-connect',
                                                                                                                  'attributes': {},
                                                                                                                  'authenticationFlowBindingOverrides': {},
                                                                                                                  'fullScopeAllowed': False,
                                                                                                                  'nodeReRegistrationTimeout': 0,
                                                                                                                  'defaultClientScopes': [
                                                                                                                      'web-origins',
                                                                                                                      'roles',
                                                                                                                      'profile',
                                                                                                                      'email'],
                                                                                                                  'optionalClientScopes': [
                                                                                                                      'address',
                                                                                                                      'phone',
                                                                                                                      'offline_access',
                                                                                                                      'microprofile-jwt']})),
                                                                                          'user', 'user'),
                                                                               Credential(Realm('other',
                                                                                                'http://localhost:8080/auth/realms/other',
                                                                                                {'realm': 'other',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/other/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client1',
                                                                                                 'http://localhost:8080/auth/realms/other/client1',
                                                                                                 ClientConfig('client1',
                                                                                                              'http://localhost:8080/realms/other/clients-registrations/default/client1',
                                                                                                              {
                                                                                                                  'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313',
                                                                                                                  'clientId': 'admin-cli',
                                                                                                                  'name': '${client_admin-cli}',
                                                                                                                  'surrogateAuthRequired': False,
                                                                                                                  'enabled': True,
                                                                                                                  'alwaysDisplayInConsole': False,
                                                                                                                  'clientAuthenticatorType': 'client-secret',
                                                                                                                  'redirectUris': [],
                                                                                                                  'webOrigins': [],
                                                                                                                  'notBefore': 0,
                                                                                                                  'bearerOnly': False,
                                                                                                                  'consentRequired': False,
                                                                                                                  'standardFlowEnabled': False,
                                                                                                                  'implicitFlowEnabled': False,
                                                                                                                  'directAccessGrantsEnabled': False,
                                                                                                                  'serviceAccountsEnabled': False,
                                                                                                                  'publicClient': False,
                                                                                                                  'frontchannelLogout': False,
                                                                                                                  'protocol': 'openid-connect',
                                                                                                                  'attributes': {},
                                                                                                                  'authenticationFlowBindingOverrides': {},
                                                                                                                  'fullScopeAllowed': False,
                                                                                                                  'nodeReRegistrationTimeout': 0,
                                                                                                                  'defaultClientScopes': [
                                                                                                                      'web-origins',
                                                                                                                      'roles',
                                                                                                                      'profile',
                                                                                                                      'email'],
                                                                                                                  'optionalClientScopes': [
                                                                                                                      'address',
                                                                                                                      'phone',
                                                                                                                      'offline_access',
                                                                                                                      'microprofile-jwt']})),
                                                                                          'user', 'user'),
                                                                               Credential(Realm('master',
                                                                                                'http://localhost:8080/auth/realms/master',
                                                                                                {'realm': 'master',
                                                                                                 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB',
                                                                                                 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect',
                                                                                                 'account-service': 'http://localhost:8080/auth/realms/master/account',
                                                                                                 'tokens-not-before': 0}),
                                                                                          Client('client1',
                                                                                                 'http://localhost:8080/auth/realms/other/client1',
                                                                                                 ClientConfig('client1',
                                                                                                              'http://localhost:8080/realms/other/clients-registrations/default/client1',
                                                                                                              {
                                                                                                                  'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313',
                                                                                                                  'clientId': 'admin-cli',
                                                                                                                  'name': '${client_admin-cli}',
                                                                                                                  'surrogateAuthRequired': False,
                                                                                                                  'enabled': True,
                                                                                                                  'alwaysDisplayInConsole': False,
                                                                                                                  'clientAuthenticatorType': 'client-secret',
                                                                                                                  'redirectUris': [],
                                                                                                                  'webOrigins': [],
                                                                                                                  'notBefore': 0,
                                                                                                                  'bearerOnly': False,
                                                                                                                  'consentRequired': False,
                                                                                                                  'standardFlowEnabled': False,
                                                                                                                  'implicitFlowEnabled': False,
                                                                                                                  'directAccessGrantsEnabled': False,
                                                                                                                  'serviceAccountsEnabled': False,
                                                                                                                  'publicClient': False,
                                                                                                                  'frontchannelLogout': False,
                                                                                                                  'protocol': 'openid-connect',
                                                                                                                  'attributes': {},
                                                                                                                  'authenticationFlowBindingOverrides': {},
                                                                                                                  'fullScopeAllowed': False,
                                                                                                                  'nodeReRegistrationTimeout': 0,
                                                                                                                  'defaultClientScopes': [
                                                                                                                      'web-origins',
                                                                                                                      'roles',
                                                                                                                      'profile',
                                                                                                                      'email'],
                                                                                                                  'optionalClientScopes': [
                                                                                                                      'address',
                                                                                                                      'phone',
                                                                                                                      'offline_access',
                                                                                                                      'microprofile-jwt']})),
                                                                                          'user', 'user')}

    client1_master = Client('client1', 'http://localhost:8080/auth/realms/master/client1',
           ClientConfig('client1', 'http://localhost:8080/realms/master/clients-registrations/default/client1',
                        {'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313', 'clientId': 'admin-cli',
                         'name': '${client_admin-cli}', 'surrogateAuthRequired': False, 'enabled': True,
                         'alwaysDisplayInConsole': False, 'clientAuthenticatorType': 'client-secret',
                         'redirectUris': [], 'webOrigins': [], 'notBefore': 0, 'bearerOnly': False,
                         'consentRequired': False, 'standardFlowEnabled': False, 'implicitFlowEnabled': False,
                         'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False, 'publicClient': False,
                         'frontchannelLogout': False, 'protocol': 'openid-connect', 'attributes': {},
                         'authenticationFlowBindingOverrides': {}, 'fullScopeAllowed': False,
                         'nodeReRegistrationTimeout': 0,
                         'defaultClientScopes': ['web-origins', 'roles', 'profile', 'email'],
                         'optionalClientScopes': ['address', 'phone', 'offline_access', 'microprofile-jwt']}))

    client2_master = Client('client2', 'http://localhost:8080/auth/realms/master/client2', None)

    client1_other = Client('client1', 'http://localhost:8080/auth/realms/other/client1', ClientConfig('client1', 'http://localhost:8080/realms/other/clients-registrations/default/client1', {'id': '899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313', 'clientId': 'admin-cli', 'name': '${client_admin-cli}', 'surrogateAuthRequired': False, 'enabled': True, 'alwaysDisplayInConsole': False, 'clientAuthenticatorType': 'client-secret', 'redirectUris': [], 'webOrigins': [], 'notBefore': 0, 'bearerOnly': False, 'consentRequired': False, 'standardFlowEnabled': False, 'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False, 'publicClient': False, 'frontchannelLogout': False, 'protocol': 'openid-connect', 'attributes': {}, 'authenticationFlowBindingOverrides': {}, 'fullScopeAllowed': False, 'nodeReRegistrationTimeout': 0, 'defaultClientScopes': ['web-origins', 'roles', 'profile', 'email'], 'optionalClientScopes': ['address', 'phone', 'offline_access', 'microprofile-jwt']}))

    client2_other = Client('client2', 'http://localhost:8080/auth/realms/other/client2', None)


    # TODO: test when find vuln
    assert scanner.mediator.scan_results.get(WrapperTypes.OPEN_REDIRECT) == {
        OpenRedirect(master_realm, client1_master),
        OpenRedirect(master_realm, client2_master),
        OpenRedirect(other_realm, client1_other),
        OpenRedirect(other_realm, client2_other),

        # TODO: this is bad, url need conditions
        OpenRedirect(master_realm, client1_other),
        OpenRedirect(master_realm, client2_other),
        OpenRedirect(other_realm, client1_master),
        OpenRedirect(other_realm, client2_master),

    }

    assert scanner.mediator.scan_results.get(WrapperTypes.FORM_POST_XSS) == set()

    assert scanner.mediator.scan_results.get(WrapperTypes.REALM_TYPE) == {master_realm, other_realm}

    assert scanner.mediator.scan_results.get(WrapperTypes.SECURITY_CONSOLE) == set()

    assert scanner.mediator.scan_results.get(WrapperTypes.WELL_KNOWN_TYPE) == {well_known_master, well_known_other}
