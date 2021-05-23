from termcolor import colored

from keycloak_scanner.logging.root_logger import RootLogger


class PrintLogger(RootLogger):

    def __init__(self, verbose=False, **kwargs):
        self.verbose = verbose
        super().__init__(**kwargs)

    def warn(self, message: str):
        print(f'[WARN] {message}')
        super().warn(message)

    def info(self, message: str):
        print('[INFO] {}'.format(message))
        super().info(message)

    def verbose(self, message: str, color='grey'):
        if self.verbose:
            print(colored('[VERBOSE] {}'.format(message), color))
        super().verbose(message, color)

    def find(self, scanner: str, message: str, color='red'):
        super().find(scanner, message, color)
