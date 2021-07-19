import argparse
import sys

import requests
import urllib3

from keycloak_scanner.scan_base.types import Username, Password
from keycloak_scanner.scan_base.wrap import WrapperTypes
from keycloak_scanner.scanners.clientregistration_scanner import ClientRegistrationScanner
from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.login_scanner import LoginScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scan_base.session_holder import SessionProvider
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner
from keycloak_scanner._version import __version__


def parser():
    parser = argparse.ArgumentParser(description='KeyCloak vulnerabilities scanner.',
                                     epilog='''

Scans : 
- list realms
- Search well-known files
- Search for clients
- Search for valid logins
- Try client registration
- Search for security-admin-console and secret inside
- Search for open redirect via unvalidated redirect_uri
- Search for CVE-2018-14655 (reflected XSS)
- None alg in refresh token

Bugs, feature requests, request another scan, questions : https://github.com/NeuronAddict/keycloak-scanner.

*** Use it on production systems at your own risk ***
''',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('base_url', help='URL to scan. ex http://localhost:8080')
    parser.add_argument('--realms', help='Comma separated list of custom realms to test. Default: master', default='master')
    parser.add_argument('--clients', help='Comma separated list of custom clients to test. Default: account,admin-cli,broker,realm-management,security-admin-console',
                        default='account,admin-cli,broker,realm-management,security-admin-console')
    parser.add_argument('--proxy', help='Use an http proxy. ex: http://127.0.0.1:8080')
    parser.add_argument('--username', help='If a username is specified, try to connect and attack a token. If no '
                                           'password, try username as password.')
    parser.add_argument('--password', help='password to test with username')
    parser.add_argument('--ssl-noverify', help='Do not verify ssl certificates', action='store_true')
    parser.add_argument('--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('--no-fail', action='store_true',
                        help='Always exit with code 0 (by default, fail with an exit code 4 if a vulnerability is '
                             'discovered or 8 if an error occur). '
                             'Do NOT fail before all test are done.')
    parser.add_argument('--fail-fast', action='store_true', help='Fail immediately if an error occur.')
    parser.add_argument('--version', action='version', version=f'keycloak-scanner {__version__}. '
                                                               f'https://github.com/NeuronAddict/keycloak-scanner.')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--registration-callback', help='Callback url to use on client registration test',
                       default='http://localhost')
    group.add_argument('--registration-callback-list', help='File with one callback to test for registration by line')

    return parser


def main():

    args = parser().parse_args()

    start(args, lambda: requests.Session())


def start(args, initial_session_provider: SessionProvider):

    realms = args.realms.split(',') if args.realms else []
    clients = args.clients.split(',') if args.clients else []

    def session_provider() -> requests.session():

        session = initial_session_provider()

        if args.proxy:
            session.proxies = {'http': args.proxy, 'https': args.proxy}

        if args.ssl_noverify:
            session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return session

    common_args = {
        'base_url': args.base_url,
        'verbose': args.verbose,
        'session_provider': session_provider
    }

    scanner = MasterScanner(scanners=[
        RealmScanner(realms=realms, **common_args),
        WellKnownScanner(**common_args),
        ClientScanner(clients=clients, **common_args),
        LoginScanner(**common_args),
        ClientRegistrationScanner(**common_args,
                                  callback_url=[args.registration_callback] if args.registration_callback else args.registration_callback_list), # TODO: list + file when str can confuse
        SecurityConsoleScanner(**common_args),
        OpenRedirectScanner(**common_args),
        FormPostXssScanner(**common_args),
        NoneSignScanner(**common_args)
    ], initial_values={
        WrapperTypes.USERNAME_TYPE: [Username(args.username)],
        WrapperTypes.PASSWORD_TYPE: [Password(args.password)],
    }, verbose=args.verbose, fail_fast=True)
    status = scanner.start()

    if not args.no_fail and status.has_vulns:
        print('Fail with exit code 4 because vulnerabilities are discovered')
        sys.exit(4)

    if status.has_error:
        print('No vulns but error(s) are returned, exit with code 8')
        sys.exit(8)

