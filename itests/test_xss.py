import os

import pytest
import requests

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


@pytest.mark.skipif(os.getenv('ITESTS_XSS') != 'true', reason='integration tests')
def test_should_start_scan_xss_fail_security_console_exit_4(base_url: str, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console',
                         '--username', 'admin', '--password', 'Pa55w0rd'])

    with pytest.raises(SystemExit) as e:
        start(args, lambda: requests.Session())

    assert e.value.code == 4

    captured = capsys.readouterr()

    print(captured.out)

    print(captured.err)

    assert captured.err == ''

    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : ' in captured.out

    assert "Find a well known for realm Realm('master'," in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    assert "[INFO] Find a client auth endpoint for realm master: security-admin-console" in captured.out

# TODO may be work after fix client scanner with registration
#    assert "[+] LoginScanner - Form login work for admin on realm master, client security-admin-console" in captured.out

    assert "[+] LoginScanner - Can login with username admin on realm master, client admin-cli, grant_type: password" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKWZJFM1kaPeoKviEIFCdeH4oCnIIKGuC1qqagw6lsDwqUPMEBSrwDZ8NETm2RW87OE8aK0IzUexRI7aaIsAurdboS/2fKmvnBfRh17q307wypci/SDaKdYdLbjHN3Be74mOSxHaYstaNBWhqfj8naOpqYP3ukv2n8PvdQvrK3qZMyfxX3RwgW0Onrff67PGKORPxYWw3FhoxjLIY6KSHLEGCVPDOhXZZxdTGApOaXCBL5V1asnSKJIz3js/yn9Zp2UWR+I4fQXwcdluwaO/ZOp0STUQKI3rNjjdqox7srgkeP4a05Xi+YuKizM2ARo4Q4OX81fcJVpNhTCKabY9EQIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), client:Client('account', 'http://localhost:8080/auth/realms/master/account', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKWZJFM1kaPeoKviEIFCdeH4oCnIIKGuC1qqagw6lsDwqUPMEBSrwDZ8NETm2RW87OE8aK0IzUexRI7aaIsAurdboS/2fKmvnBfRh17q307wypci/SDaKdYdLbjHN3Be74mOSxHaYstaNBWhqfj8naOpqYP3ukv2n8PvdQvrK3qZMyfxX3RwgW0Onrff67PGKORPxYWw3FhoxjLIY6KSHLEGCVPDOhXZZxdTGApOaXCBL5V1asnSKJIz3js/yn9Zp2UWR+I4fQXwcdluwaO/ZOp0STUQKI3rNjjdqox7srgkeP4a05Xi+YuKizM2ARo4Q4OX81fcJVpNhTCKabY9EQIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), client:Client('account', 'http://localhost:8080/auth/realms/master/account', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKWZJFM1kaPeoKviEIFCdeH4oCnIIKGuC1qqagw6lsDwqUPMEBSrwDZ8NETm2RW87OE8aK0IzUexRI7aaIsAurdboS/2fKmvnBfRh17q307wypci/SDaKdYdLbjHN3Be74mOSxHaYstaNBWhqfj8naOpqYP3ukv2n8PvdQvrK3qZMyfxX3RwgW0Onrff67PGKORPxYWw3FhoxjLIY6KSHLEGCVPDOhXZZxdTGApOaXCBL5V1asnSKJIz3js/yn9Zp2UWR+I4fQXwcdluwaO/ZOp0STUQKI3rNjjdqox7srgkeP4a05Xi+YuKizM2ARo4Q4OX81fcJVpNhTCKabY9EQIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), client:Client('security-admin-console', 'None', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')" in captured.out

    assert "[+] XSS-CVE2018-14655 - Vulnerable to CVE 2018 14655 realm:Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKWZJFM1kaPeoKviEIFCdeH4oCnIIKGuC1qqagw6lsDwqUPMEBSrwDZ8NETm2RW87OE8aK0IzUexRI7aaIsAurdboS/2fKmvnBfRh17q307wypci/SDaKdYdLbjHN3Be74mOSxHaYstaNBWhqfj8naOpqYP3ukv2n8PvdQvrK3qZMyfxX3RwgW0Onrff67PGKORPxYWw3FhoxjLIY6KSHLEGCVPDOhXZZxdTGApOaXCBL5V1asnSKJIz3js/yn9Zp2UWR+I4fQXwcdluwaO/ZOp0STUQKI3rNjjdqox7srgkeP4a05Xi+YuKizM2ARo4Q4OX81fcJVpNhTCKabY9EQIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}), client:Client('security-admin-console', 'None', 'http://localhost:8080/auth/realms/master/protocol/openid-connect/auth')" in captured.out
