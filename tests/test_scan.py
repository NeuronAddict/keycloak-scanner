from typing import List
from unittest.mock import MagicMock

import requests
from requests import Session

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner, FormPostXssResult
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner, NoneSignResult
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner, OpenRedirect
from keycloak_scanner.scanners.realm_scanner import RealmScanner, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner, WellKnown
from tests.mock_response import MockPrintLogger


class TestResult:
    pass


class TestResultList(List[str], MockPrintLogger):
    pass


class TestScanner(Scanner[TestResult], MockPrintLogger):
    def perform(self):
        super().session().get(super().base_url())
        return TestResult()


class TestScannerList(Scanner[TestResultList], MockPrintLogger):
    def perform(self):
        super().session().get(super().base_url())
        return TestResultList(), VulnFlag(True)


class TestMasterScanner(MasterScanner, MockPrintLogger):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


def test_start():
    session = requests.Session()
    session.get = MagicMock()
    scanner = MasterScanner([TestScanner(base_url='https://testscan', session=session)])
    scanner.start()
    session.get.assert_called_with('https://testscan')


def test_should_fail_when_scanner_return_empty_list():
    session = requests.Session()
    session.get = MagicMock()
    test_scanner = TestScannerList(base_url='https://testscan', session=session)
    scanner = TestMasterScanner(scans=[test_scanner])
    scanner.start()
    assert scanner.warns == [
        'Result of TestScannerList as no results (void list), subsequent scans can be void too.'
    ]


def test_full_scan(base_url: str, full_scan_mock_session: Session):
    scans = [
        RealmScanner(base_url=base_url, session=full_scan_mock_session, realms=['master', 'other']),
        WellKnownScanner(base_url=base_url, session=full_scan_mock_session),
        ClientScanner(base_url=base_url, session=full_scan_mock_session, clients=['client1', 'client2']),
        SecurityConsoleScanner(base_url=base_url, session=full_scan_mock_session),
        OpenRedirectScanner(base_url=base_url, session=full_scan_mock_session),
        FormPostXssScanner(base_url=base_url, session=full_scan_mock_session),
        NoneSignScanner(base_url=base_url, session=full_scan_mock_session)
    ]

    scanner = MasterScanner(scans=scans, verbose=True)
    scanner.start()

    print(repr(scanner.results))

    assert scanner.results.results == {'clients': [Client('client1', 'http://localhost:8080/auth/realms/master/client1', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'),
             Client('client2', 'http://localhost:8080/auth/realms/master/client2', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'),
             Client('client1', 'http://localhost:8080/auth/realms/other/client1', 'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth'),
             Client('client2', 'http://localhost:8080/auth/realms/other/client2', 'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth')],
 'form_post_xss_results': {'master': FormPostXssResult(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), False),
                           'other': FormPostXssResult(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0}), False)},
 'none_sign_results': {'master': NoneSignResult(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), False),
                       'other': NoneSignResult(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0}), False)},
 'open_redirect': OpenRedirect({'master-client1': True, 'master-client2': True, 'other-client1': True, 'other-client2': True}),
 'realms': [Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}),
            Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0})],
 'security_console_results': {},
 'well_known_dict': {'master': WellKnown(Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), name='master', url='http://localhost:8080/auth/realms/master/.well-known/openid-configuration', json={'issuer': 'http://localhost:8080/auth/realms/master', 'authorization_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth', 'token_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token', 'introspection_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token/introspect', 'userinfo_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo', 'end_session_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/logout', 'jwks_uri': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/certs', 'check_session_iframe': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/login-status-iframe.html', 'grant_types_supported': ['authorization_code', 'implicit', 'refresh_token', 'password', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:openid:params:grant-type:ciba'], 'response_types_supported': ['code', 'none', 'id_token', 'token', 'id_token token', 'code id_token', 'code token', 'code id_token token'], 'subject_types_supported': ['public', 'pairwise'], 'id_token_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'id_token_encryption_alg_values_supported': ['RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5'], 'id_token_encryption_enc_values_supported': ['A256GCM', 'A192GCM', 'A128GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'], 'userinfo_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512', 'none'], 'request_object_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512', 'none'], 'response_modes_supported': ['query', 'fragment', 'form_post'], 'registration_endpoint': 'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect', 'token_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'token_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'introspection_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'introspection_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'claims_supported': ['aud', 'sub', 'iss', 'auth_time', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'acr'], 'claim_types_supported': ['normal'], 'claims_parameter_supported': 'true', 'scopes_supported': ['openid', 'web-origins', 'offline_access', 'address', 'phone', 'microprofile-jwt', 'roles', 'profile', 'email'], 'request_parameter_supported': 'true', 'request_uri_parameter_supported': 'true', 'require_request_uri_registration': 'true', 'code_challenge_methods_supported': ['plain', 'S256'], 'tls_client_certificate_bound_access_tokens': 'true', 'revocation_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/revoke', 'revocation_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'revocation_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'backchannel_logout_supported': 'true', 'backchannel_logout_session_supported': 'true', 'device_authorization_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth/device', 'backchannel_token_delivery_modes_supported': ['poll'], 'backchannel_authentication_endpoint': 'http://localhost:8080/auth/realms/master/protocol/openid-connect/ext/ciba/auth'}),
                     'other': WellKnown(Realm('other', 'http://localhost:8080/auth/realms/other', {'realm': 'other', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/other/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/other/account', 'tokens-not-before': 0}), name='other', url='http://localhost:8080/auth/realms/other/.well-known/openid-configuration', json={'issuer': 'http://localhost:8080/auth/realms/other', 'authorization_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth', 'token_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/token', 'introspection_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/token/introspect', 'userinfo_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/userinfo', 'end_session_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/logout', 'jwks_uri': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/certs', 'check_session_iframe': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/login-status-iframe.html', 'grant_types_supported': ['authorization_code', 'implicit', 'refresh_token', 'password', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:openid:params:grant-type:ciba'], 'response_types_supported': ['code', 'none', 'id_token', 'token', 'id_token token', 'code id_token', 'code token', 'code id_token token'], 'subject_types_supported': ['public', 'pairwise'], 'id_token_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'id_token_encryption_alg_values_supported': ['RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5'], 'id_token_encryption_enc_values_supported': ['A256GCM', 'A192GCM', 'A128GCM', 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'], 'userinfo_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512', 'none'], 'request_object_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512', 'none'], 'response_modes_supported': ['query', 'fragment', 'form_post'], 'registration_endpoint': 'http://localhost:8080/auth/realms/other/clients-registrations/openid-connect', 'token_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'token_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'introspection_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'introspection_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'claims_supported': ['aud', 'sub', 'iss', 'auth_time', 'name', 'given_name', 'family_name', 'preferred_username', 'email', 'acr'], 'claim_types_supported': ['normal'], 'claims_parameter_supported': 'true', 'scopes_supported': ['openid', 'web-origins', 'offline_access', 'address', 'phone', 'microprofile-jwt', 'roles', 'profile', 'email'], 'request_parameter_supported': 'true', 'request_uri_parameter_supported': 'true', 'require_request_uri_registration': 'true', 'code_challenge_methods_supported': ['plain', 'S256'], 'tls_client_certificate_bound_access_tokens': 'true', 'revocation_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/revoke', 'revocation_endpoint_auth_methods_supported': ['private_key_jwt', 'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'client_secret_jwt'], 'revocation_endpoint_auth_signing_alg_values_supported': ['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256', 'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'], 'backchannel_logout_supported': 'true', 'backchannel_logout_session_supported': 'true', 'device_authorization_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth/device', 'backchannel_token_delivery_modes_supported': ['poll'], 'backchannel_authentication_endpoint': 'http://localhost:8080/auth/realms/other/protocol/openid-connect/ext/ciba/auth'})}}