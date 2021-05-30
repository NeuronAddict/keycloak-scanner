import pytest
from requests import Session

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


def test_should_full_scan_exit_code_4_when_vuln(base_url: str, full_scan_mock_session: Session):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'other', '--clients', 'client1,client2',
                         '--username', 'username', '--password', 'password', '--verbose',
                         '--registration-callback', 'http://localhost:8080'
                         ])

    with pytest.raises(SystemExit) as e:

        start(args, lambda: full_scan_mock_session)

    assert e.value.code == 4
