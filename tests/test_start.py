import argparse
from unittest.mock import MagicMock

import requests
from pytest import fixture

from keycloak_scanner.main import start
from keycloak_scanner.main import parser

class MockResponse:
    status_code = 200

    text = 'coucou'

    def json(self):
        return {'response_types_supported': ['code'],
                'authorization_endpoint': 'http://testscan/auth',
                'response_modes_supported': ['form_post']
                }


# TODO : factorize this conf
@fixture
def well_known():
    return MockResponse()


def test_start(well_known):

    session = requests.Session()
    session.get = MagicMock(return_value=well_known)
    session.post = MagicMock()
    session.put = MagicMock()
    session.delete = MagicMock()

    p = parser()

    args = p.parse_args(['http://localhost', '--realms', 'test-realm', '--clients', 'test-client', '--username', 'username', '--password', 'password', '--no-fail'])

    start(args, session)
