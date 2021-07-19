import os

import pytest
import requests
from _pytest.capture import CaptureFixture

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


@pytest.mark.skipif(os.getenv('ITESTS_XSS') != 'true', reason='integration tests')
def test_should_start_scan_xss_fail_security_console_exit_4(base_url: str, capsys: CaptureFixture, proxy: str):
    p = parser()

    base_args = [base_url, '--realms', 'master', '--clients',
                 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                 '--username', 'admin', '--password', 'Pa55w0rd', '--registration-callback', 'http://localhost:8080']

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

    # TODO may be work after fix client scanner with registration
    #    assert "[+] LoginScanner - Form login work for admin on realm master, client security-admin-console" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm master, client admin-cli, grant_type: password" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:master, client:account" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:master, client:account" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:master, client:security-admin-console" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:master, client:security-admin-console" in captured.out
