from pathlib import Path
from typing import List

from _pytest.fixtures import fixture
from requests import Session

from keycloak_scanner.scan_base.types import Realm, SecurityConsole, WellKnown, Client

from tests.mock_response import MockResponse, RequestSpec, MockSpec


# httpclient_logging_patch()


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



@fixture
def well_known_master(master_realm: Realm, well_known_json_master: dict) -> WellKnown:
    return WellKnown(realm=master_realm, name='master',
                      url='http://localhost:8080/auth/realms/master/.well-known/openid-configuration',
                      json=well_known_json_master)


@fixture
def well_known_other(other_realm: Realm, well_known_json_other: dict) -> WellKnown:
    return WellKnown(realm=other_realm, name='other',
                      url='http://localhost:8080/auth/realms/other/.well-known/openid-configuration',
                      json=well_known_json_other)


@fixture
def well_known_list(well_known_master: WellKnown, well_known_other: WellKnown) -> List[WellKnown]:
    # TODO: master wk json in all
    return [well_known_master, well_known_other]


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
def all_realms(master_realm: Realm, other_realm: Realm) -> List[Realm]:
    return [master_realm, other_realm]


@fixture
def other_realm(other_realm_json: dict) -> Realm:
    return Realm('other', 'http://localhost:8080/auth/realms/other', json=other_realm_json)


@fixture
def client1() -> Client:
    return Client(name='client1', url='http://localhost:8080/auth/realms/master/client1')


@fixture
def client2() -> Client:
    return Client(name='client2', url='http://localhost:8080/auth/realms/master/client2')


@fixture
def all_clients(client1: Client, client2: Client) -> List[Client]:
    return [client1, client2]


@fixture
def security_console_results(master_realm: Realm, other_realm: Realm) -> List[SecurityConsole]:
    return [
         SecurityConsole(master_realm,
                                        'http://localhost:8080/auth/realms/master/clients-registrations/default/security-admin-console',
                                        json={}),

         SecurityConsole(other_realm,
                                       'http://localhost:8080/auth/realms/other/clients-registrations/default/security-admin-console',
                                       json={}, secret={'secret': 'secretdata'}),
    ]


@fixture
def login_html_page():
    return '''
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" class="login-pf">

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="robots" content="noindex, nofollow">

            <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>Sign in to Keycloak</title>
    <link rel="icon" href="/auth/resources/p4o5n/login/keycloak/img/favicon.ico" />
            <link href="/auth/resources/p4o5n/common/keycloak/web_modules/@patternfly/react-core/dist/styles/base.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/common/keycloak/web_modules/@patternfly/react-core/dist/styles/app.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/common/keycloak/node_modules/patternfly/dist/css/patternfly.min.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/common/keycloak/node_modules/patternfly/dist/css/patternfly-additions.min.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/common/keycloak/lib/pficon/pficon.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/login/keycloak/css/login.css" rel="stylesheet" />
            <link href="/auth/resources/p4o5n/login/keycloak/css/tile.css" rel="stylesheet" />
</head>

<body class="">
<div class="login-pf-page">
    <div id="kc-header" class="login-pf-page-header">
        <div id="kc-header-wrapper"
             class=""><div class="kc-logo-text"><span>Keycloak</span></div></div>
    </div>
    <div class="card-pf">
        <header class="login-pf-header">
                <h1 id="kc-page-title">        Sign in to your account

</h1>
      </header>
      <div id="kc-content">
        <div id="kc-content-wrapper">


    <div id="kc-form">
      <div id="kc-form-wrapper">
            <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="http://localhost:8080/auth/realms/master/login-actions/authenticate?session_code=bR4rBd0QNGsd_kGuqiyLEuYuY6FK3Lx9HCYJEltUQBk&amp;execution=de13838a-ee3d-404e-b16d-b0d7aa320844&amp;client_id=account-console&amp;tab_id=GXMjAPR3DsQ" method="post">
                <div class="form-group">
                    <label for="username" class="pf-c-form__label pf-c-form__label-text">Username or email</label>

                        <input tabindex="1" id="username" class="pf-c-form-control" name="username" value=""  type="text" autofocus autocomplete="off"
                               aria-invalid=""
                        />

                </div>

                <div class="form-group">
                    <label for="password" class="pf-c-form__label pf-c-form__label-text">Password</label>

                    <input tabindex="2" id="password" class="pf-c-form-control" name="password" type="password" autocomplete="off"
                           aria-invalid=""
                    />
                </div>

                <div class="form-group login-pf-settings">
                    <div id="kc-form-options">
                        </div>
                        <div class="">
                        </div>

                  </div>

                  <div id="kc-form-buttons" class="form-group">
                      <input type="hidden" id="id-hidden-input" name="credentialId" />
                      <input tabindex="4" class="pf-c-button pf-m-primary pf-m-block btn-lg" name="login" id="kc-login" type="submit" value="Sign In"/>
                  </div>
            </form>
        </div>


    </div>



        </div>
      </div>

    </div>
  </div>
</body>
</html>
   
    '''


@fixture
def full_scan_mock(master_realm_json, other_realm_json, well_known_json_master: dict,
                   well_known_json_other: dict, login_html_page: str) -> MockSpec:
    token_response = {
        'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI',
        'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'
    }

    return MockSpec(get={
        'http://localhost:8080/auth/realms/master/.well-known/openid-configuration': RequestSpec(
            MockResponse(status_code=200, response=well_known_json_master)
        ),
        'http://localhost:8080/auth/realms/master': RequestSpec(
            MockResponse(status_code=200, response=master_realm_json)),
        'http://localhost:8080/auth/realms/other': RequestSpec(
            MockResponse(status_code=200, response=other_realm_json)),
        'http://localhost:8080/auth/realms/other/.well-known/openid-configuration': RequestSpec(
            MockResponse(status_code=200,
                         response=well_known_json_other)),
        'http://localhost:8080/auth/realms/master/client1': RequestSpec(
            MockResponse(status_code=200, response='coucou')),
        'http://localhost:8080/auth/realms/master/client2': RequestSpec(
            MockResponse(status_code=200, response='coucou')),
        'http://localhost:8080/auth/realms/other/client1': RequestSpec(
            MockResponse(status_code=200, response='coucou')),
        'http://localhost:8080/auth/realms/other/client2': RequestSpec(
            MockResponse(status_code=200, response='coucou')),
        'http://localhost:8080/auth/realms/master/clients-registrations/default/security-admin-console':
            RequestSpec(MockResponse(status_code=401, response={"error": "invalid_token",
                                                                "error_description": "Not authorized to view client. Not valid token or client credentials provided."})),
        'http://localhost:8080/auth/realms/other/clients-registrations/default/security-admin-console': RequestSpec(
            MockResponse(
                status_code=401, response={"error": "invalid_token",
                                           "error_description": "Not authorized to view client. Not valid token or client credentials provided."})),
        'http://localhost:8080/auth': RequestSpec(MockResponse(status_code=400)),
        'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth': RequestSpec(MockResponse(200,
                                                                                                          response=login_html_page)),
        'http://localhost:8080/auth/realms/other/protocol/openid-connect/auth': RequestSpec(MockResponse(200,
                                                                                                         response=login_html_page)),
        'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?client_id=account-console&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Frealms%2Fmaster%2Faccount%2F%23%2F&state=310f298c-f3d8-4c42-8ebc-44484febf84c&response_mode=fragment&response_type=code&scope=openid&nonce=a6be5274-15e4-4ffe-9905-ffb038b20a8e&code_challenge=Nd1svU3YNT0r6eWHkSmNeX_cxgUPQUVzPfZFXRWaJmY&code_challenge_method=S256':
            RequestSpec(MockResponse(
                200, login_html_page)),
        'http://localhost:8080/realms/master/clients-registrations/default/client1': RequestSpec(
            MockResponse(200, response={"id": "899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313", "clientId": "admin-cli",
                                        "name": "${client_admin-cli}", "surrogateAuthRequired": False, "enabled": True,
                                        "alwaysDisplayInConsole": False, "clientAuthenticatorType": "client-secret",
                                        "redirectUris": [], "webOrigins": [], "notBefore": 0, "bearerOnly": False,
                                        "consentRequired": False, "standardFlowEnabled": False,
                                        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
                                        "serviceAccountsEnabled": False, "publicClient": False,
                                        "frontchannelLogout": False, "protocol": "openid-connect", "attributes": {},
                                        "authenticationFlowBindingOverrides": {}, "fullScopeAllowed": False,
                                        "nodeReRegistrationTimeout": 0,
                                        "defaultClientScopes": ["web-origins", "roles", "profile", "email"],
                                        "optionalClientScopes": ["address", "phone", "offline_access",
                                                                 "microprofile-jwt"]})
        ),
        'http://localhost:8080/realms/other/clients-registrations/default/client1': RequestSpec(
            MockResponse(200, response={"id": "899e2dc1-5fc0-4eaf-bedb-f81a3f9e9313", "clientId": "admin-cli",
                                        "name": "${client_admin-cli}", "surrogateAuthRequired": False, "enabled": True,
                                        "alwaysDisplayInConsole": False, "clientAuthenticatorType": "client-secret",
                                        "redirectUris": [], "webOrigins": [], "notBefore": 0, "bearerOnly": False,
                                        "consentRequired": False, "standardFlowEnabled": False,
                                        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
                                        "serviceAccountsEnabled": False, "publicClient": False,
                                        "frontchannelLogout": False, "protocol": "openid-connect", "attributes": {},
                                        "authenticationFlowBindingOverrides": {}, "fullScopeAllowed": False,
                                        "nodeReRegistrationTimeout": 0,
                                        "defaultClientScopes": ["web-origins", "roles", "profile", "email"],
                                        "optionalClientScopes": ["address", "phone", "offline_access",
                                                                 "microprofile-jwt"]})
        ),
        'http://localhost:8080/realms/master/clients-registrations/default/client2': RequestSpec(
            MockResponse(400)
        ),
        'http://localhost:8080/realms/other/clients-registrations/default/client2': RequestSpec(
            MockResponse(400)
        ),

    },
        post={
            'http://localhost:8080/master/token': RequestSpec(MockResponse(status_code=200, response=token_response)),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/token': RequestSpec(
                MockResponse(status_code=200,
                             response=token_response)),
            'http://localhost:8080/other/token': RequestSpec(MockResponse(status_code=200, response=token_response)),
            'http://localhost:8080/auth/realms/other/protocol/openid-connect/token': RequestSpec(
                MockResponse(status_code=200,
                             response=token_response)),
            'http://localhost:8080/auth/realms/master/login-actions/authenticate?session_code'
            '=bR4rBd0QNGsd_kGuqiyLEuYuY6FK3Lx9HCYJEltUQBk&execution=de13838a-ee3d-404e-b16d-b0d7aa320844&client_id'
            '=account-console&tab_id=GXMjAPR3DsQ':
                RequestSpec(MockResponse(
                    302, response=None, headers={'Location': '<openid location>'})),
            'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect':
                RequestSpec(response=MockResponse(status_code=201, response={
                    "redirect_uris":
                        ["http://localhost:8080/callback"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code", "none"],
                    "client_id": "539ce782-5d15-4256-a5fa-1a46609d056b",
                    "client_secret": "c94f5fc0-0a04-4e2f-aec6-b1f5edad1d44",
                    "client_name": "keycloak-client-456789",
                    "scope": "address phone offline_access microprofile-jwt",
                    "jwks_uri": "http://localhost:8080/public_keys.jwks",
                    "subject_type": "pairwise",
                    "request_uris": ["http://localhost:8080/rf.txt"],
                    "tls_client_certificate_bound_access_tokens": False,
                    "client_id_issued_at": 1622306364,
                    "client_secret_expires_at": 0,
                    "registration_client_uri": "http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b",
                    "backchannel_logout_session_required": False
                })),
            'http://localhost:8080/auth/realms/other/clients-registrations/openid-connect':
                RequestSpec(response=MockResponse(status_code=201, response={
                    "redirect_uris":
                        ["http://localhost:8080/callback"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code", "none"],
                    "client_id": "539ce782-5d15-4256-a5fa-1a46609d056b",
                    "client_secret": "c94f5fc0-0a04-4e2f-aec6-b1f5edad1d44",
                    "client_name": "keycloak-client-456789",
                    "scope": "address phone offline_access microprofile-jwt",
                    "jwks_uri": "http://localhost:8080/public_keys.jwks",
                    "subject_type": "pairwise",
                    "request_uris": ["http://localhost:8080/rf.txt"],
                    "tls_client_certificate_bound_access_tokens": False,
                    "client_id_issued_at": 1622306364,
                    "client_secret_expires_at": 0,
                    "registration_client_uri": "http://localhost:8080/auth/realms/other/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b",
                    "backchannel_logout_session_required": False
                }))
        })


@fixture
def full_scan_mock_session(full_scan_mock: MockSpec) -> Session:
    return full_scan_mock.session()


@fixture
def callback_file(tmp_path: Path) -> Path:
    p = tmp_path / 'callback.txt'
    p.write_text('http://callback\nhttp://callback2\n')
    return p
