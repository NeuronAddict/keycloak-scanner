from unittest.mock import MagicMock

import requests
from _pytest.fixtures import fixture
from requests import Session

from keycloak_scanner.scanners.clients_scanner import Client, Clients
from keycloak_scanner.scanners.realm_scanner import Realm, Realms
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleResults, SecurityConsoleResult
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict, WellKnown
from tests.mock_response import MockResponse


@fixture
def base_url() -> str:
    return 'http://localhost:8080'


@fixture
def well_known_json_master() -> dict:
    return {"issuer": "http://localhost:8080/auth/realms/master",
            "authorization_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth",
            "token_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
            "introspection_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token/introspect",
            "userinfo_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo",
            "end_session_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/logout",
            "jwks_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs",
            "check_session_iframe": "http://localhost:8080/auth/realms/master/protocol/openid-connect/login-status-iframe.html",
            "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password",
                                      "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
                                      "urn:openid:params:grant-type:ciba"],
            "response_types_supported": ["code", "none", "id_token", "token", "id_token token", "code id_token",
                                         "code token", "code id_token token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256",
                                                      "HS384", "ES512", "PS256", "PS512", "RS512"],
            "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"],
            "id_token_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256",
                                                         "A192CBC-HS384", "A256CBC-HS512"],
            "userinfo_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256",
                                                      "HS384", "ES512", "PS256", "PS512", "RS512", "none"],
            "request_object_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256",
                                                            "RS256", "HS384", "ES512", "PS256", "PS512", "RS512",
                                                            "none"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "registration_endpoint": "http://localhost:8080/auth/realms/master/clients-registrations/openid-connect",
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic", "client_secret_post",
                                                      "tls_client_auth", "client_secret_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256",
                                                                 "RS256", "HS384", "ES512", "PS256", "PS512", "RS512"],
            "introspection_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic",
                                                              "client_secret_post", "tls_client_auth",
                                                              "client_secret_jwt"],
            "introspection_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512",
                                                                         "ES256", "RS256", "HS384", "ES512", "PS256",
                                                                         "PS512", "RS512"],
            "claims_supported": ["aud", "sub", "iss", "auth_time", "name", "given_name", "family_name",
                                 "preferred_username", "email", "acr"], "claim_types_supported": ["normal"],
            "claims_parameter_supported": 'true',
            "scopes_supported": ["openid", "web-origins", "offline_access", "address", "phone", "microprofile-jwt",
                                 "roles", "profile", "email"], "request_parameter_supported": 'true',
            "request_uri_parameter_supported": 'true', "require_request_uri_registration": 'true',
            "code_challenge_methods_supported": ["plain", "S256"], "tls_client_certificate_bound_access_tokens": 'true',
            "revocation_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/revoke",
            "revocation_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic",
                                                           "client_secret_post", "tls_client_auth",
                                                           "client_secret_jwt"],
            "revocation_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512",
                                                                      "ES256", "RS256", "HS384", "ES512", "PS256",
                                                                      "PS512", "RS512"],
            "backchannel_logout_supported": 'true', "backchannel_logout_session_supported": 'true',
            "device_authorization_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth/device",
            "backchannel_token_delivery_modes_supported": ["poll"],
            "backchannel_authentication_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/ext/ciba/auth"}


@fixture
def well_known_json_other() -> dict:
    return {"issuer": "http://localhost:8080/auth/realms/other",
            "authorization_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/auth",
            "token_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/token",
            "introspection_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/token/introspect",
            "userinfo_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/userinfo",
            "end_session_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/logout",
            "jwks_uri": "http://localhost:8080/auth/realms/other/protocol/openid-connect/certs",
            "check_session_iframe": "http://localhost:8080/auth/realms/other/protocol/openid-connect/login-status-iframe.html",
            "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password",
                                      "client_credentials", "urn:ietf:params:oauth:grant-type:device_code",
                                      "urn:openid:params:grant-type:ciba"],
            "response_types_supported": ["code", "none", "id_token", "token", "id_token token", "code id_token",
                                         "code token", "code id_token token"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256",
                                                      "HS384", "ES512", "PS256", "PS512", "RS512"],
            "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"],
            "id_token_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256",
                                                         "A192CBC-HS384", "A256CBC-HS512"],
            "userinfo_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256", "RS256",
                                                      "HS384", "ES512", "PS256", "PS512", "RS512", "none"],
            "request_object_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256",
                                                            "RS256", "HS384", "ES512", "PS256", "PS512", "RS512",
                                                            "none"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "registration_endpoint": "http://localhost:8080/auth/realms/other/clients-registrations/openid-connect",
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic", "client_secret_post",
                                                      "tls_client_auth", "client_secret_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512", "ES256",
                                                                 "RS256", "HS384", "ES512", "PS256", "PS512", "RS512"],
            "introspection_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic",
                                                              "client_secret_post", "tls_client_auth",
                                                              "client_secret_jwt"],
            "introspection_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512",
                                                                         "ES256", "RS256", "HS384", "ES512", "PS256",
                                                                         "PS512", "RS512"],
            "claims_supported": ["aud", "sub", "iss", "auth_time", "name", "given_name", "family_name",
                                 "preferred_username", "email", "acr"], "claim_types_supported": ["normal"],
            "claims_parameter_supported": 'true',
            "scopes_supported": ["openid", "web-origins", "offline_access", "address", "phone", "microprofile-jwt",
                                 "roles", "profile", "email"], "request_parameter_supported": 'true',
            "request_uri_parameter_supported": 'true', "require_request_uri_registration": 'true',
            "code_challenge_methods_supported": ["plain", "S256"], "tls_client_certificate_bound_access_tokens": 'true',
            "revocation_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/revoke",
            "revocation_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic",
                                                           "client_secret_post", "tls_client_auth",
                                                           "client_secret_jwt"],
            "revocation_endpoint_auth_signing_alg_values_supported": ["PS384", "ES384", "RS384", "HS256", "HS512",
                                                                      "ES256", "RS256", "HS384", "ES512", "PS256",
                                                                      "PS512", "RS512"],
            "backchannel_logout_supported": 'true', "backchannel_logout_session_supported": 'true',
            "device_authorization_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/auth/device",
            "backchannel_token_delivery_modes_supported": ["poll"],
            "backchannel_authentication_endpoint": "http://localhost:8080/auth/realms/other/protocol/openid-connect/ext/ciba/auth"}


@fixture()
def well_known_dict(master_realm: Realm, other_realm: Realm, well_known_json_master: dict,
                    well_known_json_other: dict) -> WellKnownDict:
    # TODO: master wk json in all
    return WellKnownDict({
        'master': WellKnown(realm=master_realm, name='master',
                            url='http://localhost:8080/auth/realms/master/.well-known/openid-configuration',
                            json=well_known_json_master),
        'other': WellKnown(realm=other_realm, name='other',
                           url='http://localhost:8080/auth/realms/other/.well-known/openid-configuration',
                           json=well_known_json_other)
    })


@fixture
def master_realm_json() -> dict:
    return {"realm": "master",
            "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB",
            "token-service": "http://localhost:8080/auth/realms/master/protocol/openid-connect",
            "account-service": "http://localhost:8080/auth/realms/master/account", "tokens-not-before": 0}


@fixture
def master_realm(master_realm_json: dict) -> Realm:
    return Realm('master', 'http://localhost:8080/auth/realms/master', json=master_realm_json)


@fixture
def other_realm_json() -> dict:
    return {"realm": "other",
            "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB",
            "token-service": "http://localhost:8080/auth/realms/other/protocol/openid-connect",
            "account-service": "http://localhost:8080/auth/realms/other/account", "tokens-not-before": 0}


@fixture
def all_realms(master_realm: Realm, other_realm: Realm) -> Realms:
    return Realms([master_realm, other_realm])


@fixture
def other_realm(other_realm_json: dict) -> Realm:
    return Realm('other', 'http://localhost:8080/auth/realms/other', json=other_realm_json)


@fixture
def client1() -> Client:
    return Client(name='client1', url='http://localhost:8080/auth/realms/master/client1',
                  auth_endpoint='http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')


@fixture
def client2() -> Client:
    return Client(name='client2', url='http://localhost:8080/auth/realms/master/client2',
                  auth_endpoint='http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')


@fixture
def all_clients(client1: Client, client2: Client) -> Clients:
    return Clients([client1, client2])


@fixture
def security_console_results(master_realm: Realm, other_realm: Realm) -> SecurityConsoleResults:
    return SecurityConsoleResults({
        'master': SecurityConsoleResult(master_realm,
                                        'http://localhost:8080/auth/realms/master/clients-registrations/default/security-admin-console',
                                        json={}),

        'other': SecurityConsoleResult(other_realm,
                                       'http://localhost:8080/auth/realms/other/clients-registrations/default/security-admin-console',
                                       json={}, secret={'secret': 'secretdata'}),
    })


@fixture
def full_scan_mock_session(master_realm_json, other_realm_json, well_known_json_master: dict,
                           well_known_json_other: dict) -> Session:
    def get_mock_response(url, **kwargs):
        responses = {
            'http://localhost:8080/auth/realms/master/.well-known/openid-configuration': MockResponse(status_code=200,
                                                                                                      response=well_known_json_master),
            'http://localhost:8080/auth/realms/master': MockResponse(status_code=200, response=master_realm_json),
            'http://localhost:8080/auth/realms/other': MockResponse(status_code=200, response=other_realm_json),
            'http://localhost:8080/auth/realms/other/.well-known/openid-configuration': MockResponse(status_code=200,
                                                                                                     response=well_known_json_other),
            'http://localhost:8080/auth/realms/master/client1': MockResponse(status_code=200, response='coucou'),
            'http://localhost:8080/auth/realms/master/client2': MockResponse(status_code=200, response='coucou'),
            'http://localhost:8080/auth/realms/other/client1': MockResponse(status_code=200, response='coucou'),
            'http://localhost:8080/auth/realms/other/client2': MockResponse(status_code=200, response='coucou'),
            'http://localhost:8080/auth/realms/master/clients-registrations/default/security-admin-console': MockResponse(
                status_code=401, response={"error": "invalid_token",
                                           "error_description": "Not authorized to view client. Not valid token or client credentials provided."}),
            'http://localhost:8080/auth/realms/other/clients-registrations/default/security-admin-console': MockResponse(
                status_code=401, response={"error": "invalid_token",
                                           "error_description": "Not authorized to view client. Not valid token or client credentials provided."}),
            'http://localhost:8080/auth': MockResponse(status_code=400),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth': MockResponse(200, response='test'),
            'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth': MockResponse(200, response='test')
        }
        if url not in responses:
            raise Exception(f'bad url test (GET) : {url}')
        return responses[url]

    def post_mock_response(url, data=None):
        if data is None:
            data = {}
        token_response = {
            'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI',
            'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'
        }
        responses = {
            'http://localhost:8080/master/token': MockResponse(status_code=200, response=token_response),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/token': MockResponse(status_code=200,
                                                                                                   response=token_response),
            'http://localhost:8080/other/token': MockResponse(status_code=200, response=token_response),
            'http://localhost:8080/auth/realms/other/protocol/openid-connect/token': MockResponse(status_code=200,
                                                                                                  response=token_response)
        }
        if url not in responses:
            raise Exception(f'bad url test (POST) : {url}')
        return responses[url]

    session = requests.Session()
    session.get = MagicMock(side_effect=get_mock_response)
    session.post = MagicMock(side_effect=post_mock_response)
    session.put = MagicMock()
    session.delete = MagicMock()

    return session
