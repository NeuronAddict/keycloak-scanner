import pytest
from requests import Session

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


def test_start(base_url: str, full_scan_mock_session: Session):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'other', '--clients', 'client1,client2',
                         '--username', 'username', '--password', 'password', '--verbose'])

    with pytest.raises(SystemExit):

        start(args, full_scan_mock_session)
