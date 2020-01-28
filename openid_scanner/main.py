import argparse
import json

from openid_scanner.scanner import Scanner
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
    args = parser.parse_args()

    start(args)


def start(args):

    realms = args.realms.split(',') if args.realms else []
    clients = args.clients.split(',') if args.clients else []

    if args.proxy:
        Request.proxy = {'http': args.proxy, 'https': args.proxy}
    Request.verify = not args.ssl_noverify

    scanner = Scanner({
        'base_url': args.base_url,
        'realms': realms,
        'clients': clients,
        'username': args.username,
        'password': args.password
    })
    scanner.start()
    #print(json.dumps(scanner.scan_properties, sort_keys=True, indent=4))
