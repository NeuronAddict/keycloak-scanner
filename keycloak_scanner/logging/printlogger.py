from termcolor import colored

from keycloak_scanner.logging.root_logger import RootLogger


class PrintLogger(RootLogger):

    def __init__(self, verbose=False, **kwargs):
        self.verbose_ = verbose
        super().__init__(**kwargs)

    def warn(self, message: str):
        print(f'[WARN] {message}')
        super().warn(message)

    def info(self, message: str):
        print('[INFO] {}'.format(message))
        super().info(message)

    def verbose(self, message: str, color='blue'):
        if self.verbose_:
            print(colored('[VERBOSE] {}'.format(message), color))
        super().verbose(message, color)

    def find(self, scanner: str, message: str, color='red'):
        print(colored(f'[+] {scanner} - {message}', 'green'))
        super().find(scanner, message, color)

    def is_verbose(self):
        return self.verbose_
