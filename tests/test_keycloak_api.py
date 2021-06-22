import pytest
import requests
from _pytest.fixtures import fixture

from keycloak_scanner.keycloak_api import KeyCloakApi, FailedAuthException
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scan_base.types import WellKnown
from tests.mock_response import MockResponse, mock_session, RequestSpec


@fixture
def access_token() -> str:
    return 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'


@fixture
def refresh_token() -> str:
    return 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'


def test_session_must_be_different_all_calls():

    kapi = KeyCloakApi(well_known={}, session_provider=lambda: requests.Session())

    assert kapi.session() != kapi.session()


def test_should_return_token(well_known_master: WellKnown):

    session_provider = lambda: mock_session(post={
        'http://localhost:8080/auth/realms/master/protocol/openid-connect/token'
        : RequestSpec(response=MockResponse(status_code=200,
                                            response={'access_token': 'access_token', 'refresh_token': 'refresh_token'}),
                      assertion=lambda **kwargs: kwargs['data'] == {'client_id': 'account',
                                                                    'client_secret': '',
                                                                    'grant_type': 'password',
                                                                    'password': 'pass',
                                                                    'username': 'user'})
    })

    kapi = KeyCloakApi(well_known=well_known_master.json, session_provider=session_provider)

    assert kapi.get_token('account', '', 'user', 'pass', 'password') == ('access_token', 'refresh_token')


def test_should_make_auth(well_known_master: WellKnown, login_html_page: str):

    session_provider = lambda: mock_session({

        'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'
        : RequestSpec(response=MockResponse(status_code=200, response=login_html_page),
                      assertion=lambda **kwargs: kwargs['params'] == {'response_type': 'code',
                                                                                       'client_id': 'account',
                                                                                       'code_challenge_method': 'S256',
                                                                                       'code_challenge': 'W59JjmjRrRjxwZVd1SZW-zfqGilWDldy2gUAMPX8EuE',
                                                                                       'redirect_uri': None})

    }, post={
        'http://localhost:8080/auth/realms/master/login-actions/authenticate?session_code=bR4rBd0QNGsd_kGuqiyLEuYuY6FK3Lx9HCYJEltUQBk&execution=de13838a-ee3d-404e-b16d-b0d7aa320844&client_id=account-console&tab_id=GXMjAPR3DsQ'
        : RequestSpec(response=MockResponse(status_code=302), assertion=lambda **kwargs: kwargs['data'] == {'password': 'pass', 'username': 'user'})
    })

    kapi = KeyCloakApi(well_known=well_known_master.json, session_provider=session_provider)

    r = kapi.auth(Client('account', url=''), password='pass', username='user')

    assert r.status_code == 302


def test_should_fail_when_bad_form_on_auth(well_known_master: WellKnown, login_html_page: str):

    session_provider = lambda: mock_session({

        'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'
        : RequestSpec(response=MockResponse(status_code=200, response='nothing'),
                      assertion=lambda **kwargs: kwargs['params'] == {'response_type': 'code',
                                                                                       'client_id': 'account',
                                                                                       'code_challenge_method': 'S256',
                                                                                       'code_challenge': 'W59JjmjRrRjxwZVd1SZW-zfqGilWDldy2gUAMPX8EuE',
                                                                                       'redirect_uri': None})

    })

    kapi = KeyCloakApi(well_known=well_known_master.json, session_provider=session_provider)

    with pytest.raises(FailedAuthException) as e:
        r = kapi.auth(Client('account', url=''), password='pass', username='user')

    assert str(e.value) == "'NoneType' object has no attribute 'attrs'"
