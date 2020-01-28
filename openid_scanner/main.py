import argparse
import json

from openid_scanner.scanner import Scanner


def main():
    parser = argparse.ArgumentParser('OpenID scanner')
    parser.add_argument('base_url')
    parser.add_argument('--realms', help='Comma separated list of custom realms to test')
    parser.add_argument('--clients', help='Comma separated list of custom clients to test')
    args = parser.parse_args()

    realms = args.realms.split(',') if args.realms else []
    clients = args.clients.split(',') if args.clients else []
    start(args.base_url, realms, clients)


def start(base_url, realms, clients):
    scanner = Scanner({
        'base_url': base_url,
        'realms': realms,
        'clients': clients
    })
    scanner.start()
    # print(json.dumps(scanner.scan_properties, sort_keys=True, indent=4))
