import os

import pytest
from requests import Session

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


@pytest.mark.skipif(os.getenv('ITESTS') != 'true', reason='integration tests')
def test_start(base_url: str, session: Session, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                         '--username', 'admin', '--password', 'pa55w0rd', '--verbose'])

    start(args, lambda: session)

    captured = capsys.readouterr()

    assert captured.err == '[WARN] Result of LoginScanner as no results (void list), subsequent scans can be void too.\n' \
                           '[WARN] Result of SecurityConsoleScanner as no results (void list), subsequent scans can be void too.\n'

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "Find a well known for realm Realm('master'," in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    # TODO: add other tests when vulns are on itest

