import pytest
from requests import Session

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


def test_start(base_url: str, session: Session, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console', '--proxy', 'http://localhost:8118',
                         '--username', 'admin', '--password', 'password', '--verbose'])

    start(args, session)

    captured = capsys.readouterr()

    assert captured.out == ''
    assert captured.err == ''
