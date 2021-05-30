import os

import pytest
import requests

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


#@pytest.mark.skipif(os.getenv('ITESTS') != 'true', reason='integration tests')
def test_should_start_scan_fail_security_console_exit_4(base_url: str, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master,other', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                         '--username', 'admin', '--password', 'Pa55w0rd', '--proxy', 'http://localhost:8118'])

    with pytest.raises(SystemExit) as e:

        start(args, lambda: requests.Session())

    assert e.value.code == 4

    captured = capsys.readouterr()

    print(captured.out)

    print(captured.err)

    assert captured.err == ''

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "Find a well known for realm master" in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    assert "[INFO] Find a client auth endpoint for realm master: security-admin-console" in captured.out

    assert "[+] LoginScanner - Form login work for admin on realm master, client security-admin-console" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm master, client admin-cli, grant_type: password" in captured.out

    assert "[+] ClientRegistrationScanner - Registering a client keycloak-client-" in captured.out

    assert "Fail with exit code 4 because vulnerabilities are discovered" in captured.out

