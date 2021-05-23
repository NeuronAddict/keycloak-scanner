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



def test_start(full_scan_mock_session):

    p = parser()

    args = p.parse_args(['http://testscan', '--realms', 'other', '--clients', 'client1,client2', '--username', 'username', '--password', 'password', '--no-fail', '--verbose'])

    start(args, full_scan_mock_session)
