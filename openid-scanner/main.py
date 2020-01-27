import argparse


def main():
    parser = argparse.ArgumentParser('OpenID scanner')
    parser.add_argument('base_url')
    parser.add_argument('realm-list', help='Comma separated list of custom realms to test')

def start(base_url, realms=[]):
    pass
