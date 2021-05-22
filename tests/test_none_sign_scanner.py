from pprint import pprint

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.logging.root_logger import RootLogger
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from tests.mock_response import MockPrintLogger


def test_perform(full_scan_mock_session):

    class TestNoneSignScanner(NoneSignScanner, MockPrintLogger):
        pass

    pprint(TestNoneSignScanner.__mro__)

    scanner = TestNoneSignScanner(username='user', password='password', base_url='http://testscan',
                              session=full_scan_mock_session)

    scan_properties = {
        'realms': {
            'master': {}
        },
        'clients': {
            'master': ['client1']
        },
        'wellknowns': {
            'master': {
                'token_endpoint': 'http://testscan/master/token'
            }
        },
        'security-admin-console': {
            'master': {
                'secret': '123456789'
            }
        }
    }
    scanner.init_scan()
    scanner.perform(scan_properties=scan_properties)

    assert scan_properties == {'clients': {'master': ['client1']},
                               'realms': {'master': {}},
                               'security-admin-console': {'master': {'secret': '123456789'}},
                               'wellknowns': {'master': {'token_endpoint': 'http://testscan/master/token'}}}

    assert scanner.infos == [
        'Start logger TestNoneSignScanner',
        'Got token via password method. access_token:eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI, '
        'refresh_token:eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI'
    ]

    assert scanner.verboses == [

    ]
