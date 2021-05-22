from termcolor import colored

from keycloak_scanner.logging.root_logger import RootLogger


class PrintLogger(RootLogger):

    def __init__(self, verbose=False, **kwargs):
        self.verbose = verbose
        super().__init__(**kwargs)

    def info(self, msg):
        print('[INFO] {}'.format(msg))
        super().info(msg)

    def verbose(self, msg, color='grey'):
        if self.verbose:
            print(colored('[VERBOSE] {}'.format(msg), color))
        super().verbose(msg, color)
