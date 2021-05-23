import argparse
import json
import sys

import requests
import urllib3


from keycloak_scanner.scanners.clients_scanner import ClientScanner
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner
from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner
from keycloak_scanner.scanners.open_redirect_scanner import OpenRedirectScanner
from keycloak_scanner.scanners.realm_scanner import RealmScanner
from keycloak_scanner.masterscanner import MasterScanner
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleScanner
from keycloak_scanner.scanners.well_known_scanner import WellKnownScanner


def parser():
    parser = argparse.ArgumentParser(description='KeyCloak vulnerabilities scanner.',
                                     epilog='''
By default, master realm is already tested.
Clients always tested : account, admin-cli, broker, realm-management, security-admin-console.

Scans : 
- list realms
- Search well-known files
- Search for clients
- Search for security-admin-console and secret inside
- Search for open redirect via unvalidated redirect_uri
- Search for CVE-2018-14655 (reflected XSS)
- None alg in refresh token

Bugs, feature requests, request another scan, questions : https://github.com/NeuronAddict/keycloak-scanner.

*** Use it on production systems at your own risk ***
''',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('base_url', help='URL to scan. ex http://localhost:8080')
    parser.add_argument('--realms', help='Comma separated list of custom realms to test')
    parser.add_argument('--clients', help='Comma separated list of custom clients to test')
    parser.add_argument('--proxy', help='Use a great proxy like BURP ;)')
    parser.add_argument('--username', help='If a username is specified, try to connect and attack a token. If no '
                                           'password, try username as password.')
    parser.add_argument('--password', help='password to test with username')
    parser.add_argument('--ssl-noverify', help='Do not verify ssl certificates', action='store_true')
    parser.add_argument('--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('--no-fail', action='store_true',
                        help='Always exit with code 0 (by default, fail with an exit code 4 if a vulnerability is discovered). '
                             'Do NOT fail before all test are done.')

    return parser


def main():

    args = parser().parse_args()

    start(args, requests.Session())


def start(args, session: requests.Session):

    realms = args.realms.split(',') if args.realms else []
    clients = args.clients.split(',') if args.clients else []

    if args.proxy:
        session = {'http': args.proxy, 'https': args.proxy}

    if args.ssl_noverify:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scanner = MasterScanner(scans=[
        RealmScanner(base_url=args.base_url, session=session, realms=realms),
        WellKnownScanner(base_url=args.base_url, session=session),
        ClientScanner(base_url=args.base_url, session=session, clients=clients),
        SecurityConsoleScanner(base_url=args.base_url, session=session),
        OpenRedirectScanner(base_url=args.base_url, session=session),
        FormPostXssScanner(base_url=args.base_url, session=session),
        NoneSignScanner(base_url=args.base_url, session=session)
    ], verbose=args.verbose)
    status = scanner.start()

    if not args.no_fail and status.has_vulns:
        print('Fail with exit code 4 because vulnerabilities are discovered')
        sys.exit(4)

    if status.has_error:
        print('No vulns but error(s) are returned, exit with code 8')
        sys.exit(8)

