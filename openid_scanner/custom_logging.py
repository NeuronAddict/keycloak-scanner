from termcolor import colored

verbose_mode = False

def info(msg):
    print('[*] {}'.format(msg))


def verbose(msg, color='gray'):
    if verbose_mode:
        print(colored('[*] {}'.format(msg), color))


def find(msg):
    print(colored('[+] {}'.format(msg), color='green'))

