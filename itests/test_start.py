import os

import pytest
from requests import Session

from keycloak_scanner.main import parser
from keycloak_scanner.main import start


@pytest.mark.skipif(os.getenv('ITESTS') != 'true', reason='integration tests')
def test_start(base_url: str, session: Session, capsys):

    p = parser()

    args = p.parse_args([base_url, '--realms', 'master', '--clients', 'account,account-console,admin-cli,broker,master-realm,security-admin-console', '--proxy', 'http://localhost:8118',
                         '--username', 'admin', '--password', 'pa55w0rd', '--verbose'])

    start(args, lambda: session)

    captured = capsys.readouterr()

    assert captured.err == ''
    assert 'Find realm master' in captured.out

    assert 'Public key for realm master : MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqtpQwhtA0f7FqtoHUYK4c7fQJa/3f4fBIi4UqWTREdqlp9Pggl3wCgh+AwfwIby+/+vjhqiDEHLFOrTwTDG+1UM3TMQcM9+pZsGlIXl1tIpfEVBUtt5TSLDZ0gBJSBrj9yLkS0pLSwKLcEWVbflLle/IPSL0UouBGgMudCQLCTJ3qkTeud+pIgfqwJ75sDLyp6Sqg8nUneAqjkduEeTAextYwuAkH8OJOdwn7t97zRNZSi55A6wBYBUM6aXllsAisDGsIwZJfT3E5tKwBkS9JmKwDhcBUPHeAoxBSj5wbbjA3y/s7vo2XAg1BRaanwWcUFVDJAaqmj06GAZ3R9YQkwIDAQAB' in captured.out

    assert "Find a well known for realm Realm('master'," in captured.out

    assert "[INFO] Find a client for realm master: account" in captured.out

    # TODO: add other tests when vulns are on itest

