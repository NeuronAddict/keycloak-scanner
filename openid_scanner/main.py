import argparse
import json

from scanner import Scanner


def main():
    parser = argparse.ArgumentParser('OpenID scanner')
    parser.add_argument('base_url')
    parser.add_argument('realm_list', help='Comma separated list of custom realms to test')
    args = parser.parse_args()

    start(args.base_url, args.realm_list.split(','))


def start(base_url, realms=[]):
    scanner = Scanner({'base_url': base_url, 'realms': realms})
    scanner.start()
    print(json.dumps(scanner.scan_properties, sort_keys=True, indent=4))
