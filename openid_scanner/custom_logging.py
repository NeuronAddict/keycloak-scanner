from termcolor import colored

verbose_mode = False


def info(msg):
    print('[INFO] {}'.format(msg))


def verbose(msg, color='gray'):
    if verbose_mode:
        print(colored('[VERBOSE] {}'.format(msg), color))


def find(msg):
    print(colored('[VULNERABILITY] {}'.format(msg), color='red'))

