from unittest.mock import MagicMock

import pytest
import requests
from _pytest.fixtures import fixture

from keycloak_scanner.keycloak_api import KeyCloakApi, FailedAuthException
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict
from tests.mock_response import MockResponse


@fixture
def access_token() -> str:
    return 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'


@fixture
def refresh_token() -> str:
    return 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'


@fixture
def working_session_provider(access_token: str, refresh_token: str, login_html_page: str):
    def get_mock_response(url, **kwargs):
        responses = {

            'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth': (MockResponse(200,
                                                                                                  response=login_html_page), {'response_type': 'code', 'client_id': 'account', 'code_challenge_method': 'S256', 'code_challenge': 'W59JjmjRrRjxwZVd1SZW-zfqGilWDldy2gUAMPX8EuE', 'redirect_uri': None}),

            'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Frealms%2Fmaster%2Faccount%2F%23%2F&state=310f298c-f3d8-4c42-8ebc-44484febf84c&response_mode=fragment&response_type=code&scope=openid&nonce=a6be5274-15e4-4ffe-9905-ffb038b20a8e&code_challenge=Nd1svU3YNT0r6eWHkSmNeX_cxgUPQUVzPfZFXRWaJmY&code_challenge_method=S256': (MockResponse(
                200, login_html_page), None)
        }
        if url not in responses:
            raise Exception(f'bad url test (GET) : {url}')
        assert kwargs['params'] == responses[url][1]
        return responses[url][0]

    def post_mock_response(url, data=None, **kwargs):
        if data is None:
            data = {}

        token_response = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        responses = {
            'http://localhost:8080/auth/realms/master/protocol/openid-connect/token': (MockResponse(status_code=200, response=token_response),
                                                                                       {'client_id': 'account',
                                                                                        'client_secret': '',
                                                                                        'grant_type': 'password',
                                                                                        'password': 'pass',
                                                                                        'username': 'user'}
                                                                                       ),
            'http://localhost:8080/auth/realms/master/login-actions/authenticate?session_code=bR4rBd0QNGsd_kGuqiyLEuYuY6FK3Lx9HCYJEltUQBk&execution=de13838a-ee3d-404e-b16d-b0d7aa320844&client_id=account-console&tab_id=GXMjAPR3DsQ': (MockResponse(
                302, response=None, headers={'Location': '<openid location>'}), {'password': 'pass', 'username': 'user'})
        }
        if url not in responses:
            raise Exception(f'bad url test (POST) : {url}')
        assert data == responses[url][1]
        return responses[url][0]

    def session_provider() -> requests.Session:

        session = requests.Session()
        session.get = MagicMock(side_effect=get_mock_response)
        session.post = MagicMock(side_effect=post_mock_response)

        return session

    return session_provider


def test_session_must_be_different_all_calls():
    kapi = KeyCloakApi(well_known={}, session_provider=lambda: requests.Session())

    assert kapi.session() != kapi.session()


def test_should_return_token(well_known_dict: WellKnownDict, working_session_provider, access_token, refresh_token):
    kapi = KeyCloakApi(well_known=well_known_dict['master'].json, session_provider=working_session_provider)

    assert kapi.get_token('account', '', 'user', 'pass', 'password') == (access_token, refresh_token)


def test_should_make_auth(well_known_dict: WellKnownDict, working_session_provider):
    kapi = KeyCloakApi(well_known=well_known_dict['master'].json, session_provider=working_session_provider)

    r = kapi.auth(Client('account', auth_endpoint=None, url=''), password='pass', username='user')

    assert r.status_code == 302


def test_should_fail_when_bad_form_on_auth(well_known_dict: WellKnownDict, working_session_provider):

    kapi = KeyCloakApi(well_known=well_known_dict['master'].json, session_provider=working_session_provider)

    with pytest.raises(FailedAuthException) as e:

        r = kapi.auth(Client('account', auth_endpoint=None, url=''), password='pass', username='user')

    assert str(e.value) == 'auth form not in response'
