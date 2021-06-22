from typing import List

from requests import Session


from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scan_base.types import WellKnown, SecurityConsole, Client, NoneSign, Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes
from tests.mock_response import MockPrintLogger


def test_perform(base_url: str, full_scan_mock_session: Session, all_realms: List[Realm], all_clients: List[Client],
                 well_known_list: List[WellKnown], security_console_results: List[SecurityConsole], master_realm: Realm,
                 other_realm: Realm):

    class TestNoneSignScanner(NoneSignScanner, MockPrintLogger):
        pass

    scanner = TestNoneSignScanner(username='user', password='password', base_url=base_url,
                            session_provider=lambda: full_scan_mock_session)

    mediator = Mediator([
        scanner
    ])

    mediator.send(WrapperTypes.REALM_TYPE, set(all_realms))
    mediator.send(WrapperTypes.CLIENT_TYPE, set(all_clients))
    mediator.send(WrapperTypes.WELL_KNOWN_TYPE, set(well_known_list))
    mediator.send(WrapperTypes.SECURITY_CONSOLE, set(security_console_results))

    assert mediator.scan_results.get(WrapperTypes.NONE_SIGN) == {
        NoneSign(other_realm), NoneSign(master_realm)
    }

    assert 'Got token via password method. access_token:eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI, refresh_token:eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3ODM4MGM2ZS1iODhmLTQ5NDQtOGRkZS03NTQyMDNkMjFhODEifQ.eyJleHAiOjE2MjE2NzU5NzIsImlhdCI6MTYyMTYzOTk3MiwianRpIjoiMGU2NDcxOTItMzU5ZS00NmU4LWFkYWQtNTQzNmQyNjMyZjA1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjJjMTZhY2Y1LWMwOTYtNDg5ZC1iYjFjLTU4ZTc0ZTJiZjAzMiIsInR5cCI6IlNlcmlhbGl6ZWQtSUQiLCJzZXNzaW9uX3N0YXRlIjoiZWY3ZjNjZmItMDAzZS00YzViLWEzMWQtYmI0OGFhZjAzNzk3Iiwic3RhdGVfY2hlY2tlciI6ImtKNy05MURtNVEwVXktT1JfVlJnT1d5eF91Wkh3M0ZfczktTVdlUjZRTlEifQ.6yZvyGKEH0NXmLY8nKRQMLsMQYPXq5dYCsIF3LRiOxI' in scanner.infos

    assert {'color': 'grey', 'message': 'No secret for realm master'} in scanner.verboses
