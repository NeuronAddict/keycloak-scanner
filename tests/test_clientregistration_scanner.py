from keycloak_scanner.scanners.clientregistration_scanner import ClientRegistrationScanner, ClientRegistrations, \
    ClientRegistration, RandomStr
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict
from tests.mock_response import RequestSpec, MockResponse, MockSpec


def check_request(**kwargs):
    return kwargs['json'] == {
        "application_type": "web",
        "redirect_uris": [
            "http://callback/callback"],
        "client_name": "keycloak-client-456789",
        "logo_uri": "http://callback/logo.png",
        "jwks_uri": "http://callback/public_keys.jwks"
    }


def test_client_registration_scanner_should_register(master_realm: Realm, well_known_dict: WellKnownDict):

    class TestRandomStr(RandomStr):

        def random_str(self) -> str:
            return '456789'

    class TestClientRegistrationScanner(ClientRegistrationScanner, TestRandomStr):
        pass

    response = {
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
    }

    session_provider = lambda: MockSpec(
        post={
            'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect':
                RequestSpec(response=MockResponse(status_code=201, response=response),
                            assertion=check_request, assertion_value={'json': {
                                "application_type": "web",
                                "redirect_uris": [
                                    "http://callback/callback"],
                                "client_name": "keycloak-client-456789",
                                "logo_uri": "http://callback/logo.png",
                                "jwks_uri": "http://callback/public_keys.jwks"
                            }})}).session()

    scanner = TestClientRegistrationScanner('http://callback', base_url='http://localhost:8080', session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict)

    assert result == ClientRegistrations([
        ClientRegistration(
            'keycloak-client-456789',
            'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            response
        )
    ])

    assert vf.has_vuln


def test_client_registration_scanner_should_not_register(master_realm: Realm, well_known_dict: WellKnownDict):

    class TestRandomStr(RandomStr):

        def random_str(self) -> str:
            return '456789'

    class TestClientRegistrationScanner(ClientRegistrationScanner, TestRandomStr):
        pass

    session_provider = lambda: MockSpec(
        post={
            'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect':
                RequestSpec(response=MockResponse(status_code=403),
                            assertion=check_request, assertion_value={'json': {
                                "application_type": "web",
                                "redirect_uris": [
                                    "http://callback/callback"],
                                "client_name": "keycloak-client-456789",
                                "logo_uri": "http://callback/logo.png",
                                "jwks_uri": "http://callback/public_keys.jwks"
                            }})}).session()

    scanner = TestClientRegistrationScanner('http://callback', base_url='http://localhost:8080', session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict)

    assert result == ClientRegistrations([])

    assert not vf.has_vuln