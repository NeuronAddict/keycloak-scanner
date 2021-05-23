from unittest.mock import MagicMock

import requests

from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner, WellKnown
from tests.mock_response import MockResponse


def test_perform(well_known: dict):

    session = requests.Session()
    session.get = MagicMock(return_value=MockResponse(status_code=200, response={}))

    open_redirect_scanner = OpenRedirectScanner(base_url='http://localhost', session=session)

    wk = WellKnown(well_known)

    result = open_redirect_scanner.perform(wk, ['master'], ['client1'])

    assert result.results == {'master-client1': True}
