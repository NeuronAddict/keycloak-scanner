import argparse
import json
import sys

import urllib3

import custom_logging
from keycloak_scanner.scanner import Scanner
from request import Request


def main():
    parser = argparse.ArgumentParser('OpenID scanner')
    parser.add_argument('base_url')
    parser.add_argument('--realms', help='Comma separated list of custom realms to test')
    parser.add_argument('--clients', help='Comma separated list of custom clients to test')
    parser.add_argument('--proxy')
    parser.add_argument('--username')
    parser.add_argument('--password')
    parser.add_argument('--ssl-noverify', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--fail-on-vuln', action='store_true',
                        help='fail with an exit code 4 if a vulnerability is discovered')
    args = parser.parse_args()

    start(args)


def start(args):

    realms = args.realms.split(',') if args.realms else []
    clients = args.clients.split(',') if args.clients else []

    custom_logging.verbose_mode = args.verbose

    if args.proxy:
        Request.proxy = {'http': args.proxy, 'https': args.proxy}

    if args.ssl_noverify:
        Request.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scanner = Scanner({
        'base_url': args.base_url,
        'realms': realms,
        'clients': clients,
        'username': args.username,
        'password': args.password
    })
    scanner.start()
    print(json.dumps(scanner.scan_properties, sort_keys=True, indent=4))
    if args.fail_on_vuln and custom_logging.has_vuln:
        print('Fail with exit code 4 because vulnerabilities are discovered')
        sys.exit(4)
