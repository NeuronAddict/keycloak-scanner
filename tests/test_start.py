from keycloak_scanner.main import parser
from keycloak_scanner.main import start


def test_start(full_scan_mock_session):

    p = parser()

    args = p.parse_args(['https://localhost:8080', '--realms', 'other', '--clients', 'client1,client2',
                         '--username', 'username', '--password', 'password', '--no-fail', '--verbose'])

    start(args, full_scan_mock_session)
    # TODO: fail when error