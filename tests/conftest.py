from unittest.mock import MagicMock

import requests
from _pytest.fixtures import fixture

from tests.mock_response import MockResponse


@fixture
def well_known():
    return {"issuer":"http://localhost:8080/auth/realms/master","authorization_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/auth","token_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/token","introspection_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/token/introspect","userinfo_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo","end_session_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/logout","jwks_uri":"http://localhost:8080/auth/realms/master/protocol/openid-connect/certs","check_session_iframe":"http://localhost:8080/auth/realms/master/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"response_modes_supported":["query","fragment","form_post"],"registration_endpoint":"http://localhost:8080/auth/realms/master/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported": 'true',"scopes_supported":["openid","web-origins","offline_access","address","phone","microprofile-jwt","roles","profile","email"],"request_parameter_supported": 'true',"request_uri_parameter_supported": 'true',"require_request_uri_registration": 'true',"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens": 'true',"revocation_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported": 'true',"backchannel_logout_session_supported": 'true',"device_authorization_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll"],"backchannel_authentication_endpoint":"http://localhost:8080/auth/realms/master/protocol/openid-connect/ext/ciba/auth"}


@fixture
def master_realm():
    return {"realm":"master","public_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB","token-service":"http://localhost:8080/auth/realms/master/protocol/openid-connect","account-service":"http://localhost:8080/auth/realms/master/account","tokens-not-before":0}


@fixture
def other_realm():
    return {"realm":"other","public_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbbkdpQ9J5QR4nmfNL6y/+3PaIKzoeUIa1oRI1QlmXgtD/mCURhdVi52S0xQ8XGy2HIsrrct/G6rVMPDBzqa2bdKP0uB6iuuBmeH/RyJlMCdrXYTZjG5uWt6SlI7462966iqGYq1o3crHbSnLr/9OFIJD2zFBEYJZ2Xbd9IRcGpwpCSKJ5YAs1EnmLQrEBHxdLsQyIiHy5yU8bT5otgyS4tvn0UiY04zOonsvH5XmzvaZ77fo6DV8GY79eqCECiBF2OHUhZ7GjZfcHlKzeCS4vEODntPc/FzV+eqDkv9/ikDwJ9KHsLbIUkR9Ob2JE7jHg0a76CF2N/z8tztFAruawIDAQAB","token-service":"http://localhost:8080/auth/realms/other/protocol/openid-connect","account-service":"http://localhost:8080/auth/realms/other/account","tokens-not-before":0}


@fixture
def full_scan_mock_session(master_realm, other_realm, well_known):
    def get_mock_response(url, params={}):
        responses = {
            'http://testscan/auth/realms/master/.well-known/openid-configuration': MockResponse(status_code=200,
                                                                                                response=well_known),
            'http://testscan/auth/realms/master': MockResponse(status_code=200, response=master_realm),
            'http://testscan/auth/realms/other': MockResponse(status_code=200, response=other_realm),
            'http://testscan/auth/realms/other/.well-known/openid-configuration': MockResponse(status_code=200,
                                                                                               response=well_known),
            'http://testscan/auth/realms/master/client1': MockResponse(status_code=200, response='coucou'),
            'http://testscan/auth/realms/master/client2': MockResponse(status_code=200, response='coucou'),
            'http://testscan/auth/realms/other/client1': MockResponse(status_code=200, response='coucou'),
            'http://testscan/auth/realms/other/client2': MockResponse(status_code=200, response='coucou'),
            'http://testscan/auth/realms/master/clients-registrations/default/security-admin-console': MockResponse(
                status_code=401, response={"error": "invalid_token",
                                           "error_description": "Not authorized to view client. Not valid token or client credentials provided."}),
            'http://testscan/auth/realms/other/clients-registrations/default/security-admin-console': MockResponse(
                status_code=401, response={"error": "invalid_token",
                                           "error_description": "Not authorized to view client. Not valid token or client credentials provided."}),
            'http://testscan/auth': MockResponse(status_code=400),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth': MockResponse(200, response='test')
        }
        if url not in responses:
            raise Exception(f'bad url test : {url}')
        return responses[url]

    def post_mock_response(url, data={}):
        responses = {
            'http://testscan/master/token': MockResponse(status_code=200, response={
                'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI',
                'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'
            })
        }
        if url not in responses:
            raise Exception(f'bad url test : {url}')
        return responses[url]

    session = requests.Session()
    session.get = MagicMock(side_effect=get_mock_response)
    session.post = MagicMock(side_effect=post_mock_response)
    session.put = MagicMock()
    session.delete = MagicMock()

    return session
