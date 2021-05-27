import os

import pytest
import requests

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


@pytest.mark.skipif(os.getenv('ITESTS') != 'true', reason='integration tests')
def test_should_start_scan_fail_security_console_exit_8(base_url: str, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                         '--username', 'admin', '--password', 'Pa55w0rd'])

    start(args, lambda: requests.Session())

    captured = capsys.readouterr()

    print(captured.out)

    print(captured.err)

    assert captured.err == '[WARN] Result of SecurityConsoleScanner as no results (void list), subsequent scans can be void too.\n'

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "Find a well known for realm master" in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    assert "[INFO] Find a client auth endpoint for realm master: security-admin-console" in captured.out

    assert "[+] LoginScanner - Form login work for admin on realm master, client security-admin-console" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm master, client admin-cli, grant_type: password" in captured.out

    # TODO: add other tests when vulns are on itest


