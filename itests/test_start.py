import os
from pathlib import Path

import pytest
import requests
from _pytest.capture import CaptureFixture

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


#@pytest.mark.skipif(os.getenv('ITESTS') != 'true', reason='integration tests')
def test_should_start_scan_fail_security_console_exit_4(base_url: str, capsys: CaptureFixture, proxy: str, callback_file: Path):
    p = parser()

    base_args = [base_url, '--realms', 'master,other', '--clients',
                 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                 '--username', 'admin', '--password', 'Pa55w0rd', '--proxy', 'http://localhost:8118',
                 '--registration-callback-list', str(callback_file.absolute())]

    if os.getenv('ITESTS_VERBOSE') == 'true':
        base_args.append('--verbose')

    if proxy:
        base_args.append('--proxy')
        base_args.append(proxy)

    args = p.parse_args(base_args)

    with pytest.raises(SystemExit) as e:
        start(args, lambda: requests.Session())

    assert e.value.code == 4

    captured = capsys.readouterr()

    print(captured.out)

    print(captured.err)

    assert '[WARN] Can\'t get token: 400 Client Error: Bad Request for url: http://localhost:8080/auth/realms/master/protocol/openid-connect/token' in captured.err

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "Find a well known for realm master" in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    assert "[+] ClientScanner - Find a client auth endpoint for realm master and client security-admin-console" in captured.out

    assert "[+] LoginScanner - Form login work for admin on realm master, client security-admin-console" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm master, client admin-cli, grant_type: password" in captured.out

    assert "[+] ClientRegistrationScanner - Registering a client keycloak-client-" in captured.out

    assert "[INFO] Deleted client keycloak-client-"

    assert "Fail with exit code 4 because vulnerabilities are discovered" in captured.out
