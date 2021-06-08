from pathlib import Path

from _pytest.fixtures import fixture

from keycloak_scanner.scanners.clientregistration_scanner import ClientRegistrationScanner, ClientRegistrations, \
    ClientRegistration, RandomStr
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.login_scanner import CredentialDict, Credential
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
    } or kwargs['json'] == {
               "application_type": "web",
               "redirect_uris": [
                   "http://callback2/callback"],
               "client_name": "keycloak-client-456789",
               "logo_uri": "http://callback2/logo.png",
               "jwks_uri": "http://callback2/public_keys.jwks"
           }


@fixture
def credential_dict() -> CredentialDict:
    return CredentialDict(
        {
            'master': Credential(username='tester', password='tester',
                                 client=Client('keycloak-client-456789', '', None),
                                 realm=Realm('master', '', None))
        }
    )


def test_client_registration_scanner_should_register(master_realm: Realm,
                                                     well_known_dict: WellKnownDict,
                                                     credential_dict: CredentialDict):
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

    scanner = TestClientRegistrationScanner(['http://callback'], base_url='http://localhost:8080',
                                            session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict, credential_dict)

    assert result == ClientRegistrations([
        ClientRegistration(
            'http://callback',
            name='keycloak-client-456789',
            url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            json=response
        )
    ])

    assert vf.has_vuln


def test_client_registration_scanner_should_not_register(master_realm: Realm,
                                                         well_known_dict: WellKnownDict,
                                                         credential_dict: CredentialDict):
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
                    }}),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/token': RequestSpec(
                response=MockResponse(status_code=403))
        },

    ).session()

    scanner = TestClientRegistrationScanner(['http://callback'], base_url='http://localhost:8080',
                                            session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict, credential_dict)

    assert result == ClientRegistrations([])

    assert not vf.has_vuln


def test_client_registration_scanner_should_register_callback_list(master_realm: Realm,
                                                                   well_known_dict: WellKnownDict,
                                                                   credential_dict: CredentialDict):
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

    scanner = TestClientRegistrationScanner(['http://callback', 'http://callback2'], base_url='http://localhost:8080',
                                            session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict, credential_dict)

    assert result == ClientRegistrations([
        ClientRegistration(
            'http://callback',
            name='keycloak-client-456789',
            url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            json=response
        ),
        ClientRegistration(
            'http://callback2',
            name='keycloak-client-456789',
            url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            json=response
        )
    ])

    assert vf.has_vuln


def test_client_registration_scanner_should_register_callback_file(master_realm: Realm, well_known_dict: WellKnownDict,
                                                                   callback_file: Path,
                                                                   credential_dict: CredentialDict):
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
                        }
                })}).session()

    scanner = TestClientRegistrationScanner(str(callback_file.absolute()), base_url='http://localhost:8080',
                                            session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict, credential_dict)

    assert result == ClientRegistrations([
        ClientRegistration(
            'http://callback',
            name='keycloak-client-456789',
            url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            json=response
        ),
        ClientRegistration(
            'http://callback2',
            name='keycloak-client-456789',
            url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b',
            json=response
        )
    ])

    assert vf.has_vuln

i = 0

def test_client_registration_scanner_should_register_with_token(master_realm: Realm,
                                                                well_known_dict: WellKnownDict,
                                                                credential_dict: CredentialDict):
    def check_request_auth(**kwargs):
        global i
        i = i + 1

        if i == 2:
            assert kwargs['headers']['Authorization'] == ''

        assert kwargs['json'] == {
            "application_type": "web",
            "redirect_uris": [
                "http://callback/callback"],
            "client_name": "keycloak-client-456789",
            "logo_uri": "http://callback/logo.png",
            "jwks_uri": "http://callback/public_keys.jwks"
        } or kwargs['json'] == {
                   "application_type": "web",
                   "redirect_uris": [
                       "http://callback2/callback"],
                   "client_name": "keycloak-client-456789",
                   "logo_uri": "http://callback2/logo.png",
                   "jwks_uri": "http://callback2/public_keys.jwks"
               }
        return True

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
                            assertion=check_request_auth, assertion_value={'json': {
                        "application_type": "web",
                        "redirect_uris": [
                            "http://callback/callback"],
                        "client_name": "keycloak-client-456789",
                        "logo_uri": "http://callback/logo.png",
                        "jwks_uri": "http://callback/public_keys.jwks"
                        }
                }),
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/token': RequestSpec(
                response=MockResponse(status_code=200, response={
                    'access_token': 'access_token',
                    'refresh_token': 'refresh_token'
                }))
        },

    ).session()

    scanner = TestClientRegistrationScanner(['http://callback'], base_url='http://localhost:8080',
                                            session_provider=session_provider)

    result, vf = scanner.perform(Realms([master_realm]), well_known_dict, credential_dict)

    assert result == ClientRegistrations([ClientRegistration('http://callback', name='keycloak-client-456789', url='http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b', json={'redirect_uris': ['http://localhost:8080/callback'], 'token_endpoint_auth_method': 'client_secret_basic', 'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code', 'none'], 'client_id': '539ce782-5d15-4256-a5fa-1a46609d056b', 'client_secret': 'c94f5fc0-0a04-4e2f-aec6-b1f5edad1d44', 'client_name': 'keycloak-client-456789', 'scope': 'address phone offline_access microprofile-jwt', 'jwks_uri': 'http://localhost:8080/public_keys.jwks', 'subject_type': 'pairwise', 'request_uris': ['http://localhost:8080/rf.txt'], 'tls_client_certificate_bound_access_tokens': False, 'client_id_issued_at': 1622306364, 'client_secret_expires_at': 0, 'registration_client_uri': 'http://localhost:8080/auth/realms/master/clients-registrations/openid-connect/539ce782-5d15-4256-a5fa-1a46609d056b', 'backchannel_logout_session_required': False})])

    assert vf.has_vuln
