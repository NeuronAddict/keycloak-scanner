from typing import List

from _pytest.capture import CaptureFixture

from keycloak_scanner.scanners.clients_scanner import ClientScanner, Client, ClientConfig
from keycloak_scanner.scan_base.types import WellKnown, Realm

from tests.mock_response import MockSpec, RequestSpec, MockResponse


def test_perform(base_url: str, master_realm: Realm, other_realm: Realm,
                 capsys: CaptureFixture, well_known_list: List[WellKnown]):

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
                                               RequestSpec(response=MockResponse(302), assertion=assert0),
                                            'http://localhost:8080/realms/master/clients-registrations/default/client1':
                                                RequestSpec(response=MockResponse(200, response={'data': 'coucou'})),
                                           'http://localhost:8080/realms/master/clients-registrations/default/client2':
                                               RequestSpec(response=MockResponse(200, response={'data': 'coucou'}))
                                       }
                                   ).session())

    result, vf = client_scanner.perform(realm=master_realm, well_known=well_known_list[0])

    capture = capsys.readouterr()

    print(capture.out)
    print(capture.err)

    assert result == {Client('client1', 'http://localhost:8080/auth/realms/master/client1',
                                     client_registration=ClientConfig(name='client1',
                                                                      url='http://localhost:8080/realms/master/clients-registrations/default/client1',
                                                                      json={'data': 'coucou'}
                                                                      )
                                     ),
                              Client('client2', None,
                                     client_registration=ClientConfig(name='client2',
                                                                      url='http://localhost:8080/realms/master/clients-registrations/default/client2',
                                                                      json={'data': 'coucou'}
                                                                      )
                                     )}

    assert not vf.has_vuln

    assert 'Find a client for realm master: client1' in capture.out
