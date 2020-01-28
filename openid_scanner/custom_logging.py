from termcolor import colored


def info(msg):
    print('[*] {}'.format(msg))


def error(msg, color='red'):
    print(colored('[-] {}'.format(msg), color))


def find(msg):
    print(colored('[+] {}'.format(msg), color='green'))

