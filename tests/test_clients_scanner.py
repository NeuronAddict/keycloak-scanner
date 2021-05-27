from _pytest.capture import CaptureFixture
from requests import Session

from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client, Clients
from keycloak_scanner.scanners.realm_scanner import Realm, Realms
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict
from tests.mock_response import MockSpec, RequestSpec, MockResponse


def test_perform(base_url: str, master_realm: Realm, other_realm: Realm,
                 well_known_dict: WellKnownDict, capsys: CaptureFixture):
    def assert0(**kwargs) -> bool:
        print(kwargs)
        return kwargs['params']['client_id'] in ['client1', 'client2']

    client_scanner = ClientScanner(clients=['client1', 'client2'], base_url=base_url,
                                   session_provider=lambda: MockSpec(
                                       get={
                                           'http://localhost:8080/auth/realms/master/client1':
                                               RequestSpec(response=MockResponse(status_code=200)),
                                           'http://localhost:8080/auth/realms/master/client2':
                                               RequestSpec(response=MockResponse(status_code=404)),

                                           'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth':
                                               RequestSpec(response=MockResponse(302), assertion=assert0)

                                       }
                                   ).session())

    realms = Realms([master_realm])

    result, vf = client_scanner.perform(realms=realms, well_known_dict=well_known_dict)

    capture = capsys.readouterr()

    print(capture.out)
    print(capture.err)

    assert result == Clients([Client('client1', 'http://localhost:8080/auth/realms/master/client1',
                                     'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth'),
                              Client('client2', None,
                                     'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')])

    assert not vf.has_vuln

    assert 'Find a client for realm master: client1' in capture.out
    assert 'Find a client auth endpoint for realm master: client2' in capture.out
