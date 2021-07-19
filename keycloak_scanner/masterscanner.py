from typing import List, Dict

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.wrap import WrapperType


class ScanStatus:

    def __init__(self, has_error=False, has_vulns=False):
        self.has_error = has_error
        self.has_vulns = has_vulns


class MasterScanner(PrintLogger):

    def __init__(self, scanners: List[Scanner], initial_values=None,
                 verbose=False, fail_fast=False, **kwargs):

        if initial_values is None:
            initial_values = {}

        self.mediator = Mediator(scanners, initial_values, fail_fast=fail_fast)
        self.fail_fast = fail_fast
        super().__init__(verbose=verbose, **kwargs)

    def start(self) -> ScanStatus:

        has_errors, vf = self.mediator.start()

        return ScanStatus(has_errors, vf.has_vuln)
