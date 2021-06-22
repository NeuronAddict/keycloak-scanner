from typing import List

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scan_base.mediator import Mediator
from keycloak_scanner.scan_base.scanner import Scanner


class ScanStatus:

    def __init__(self, has_error=False, has_vulns=False):
        self.has_error = has_error
        self.has_vulns = has_vulns


class MasterScanner(PrintLogger):

    def __init__(self, scanners: List[Scanner], verbose=False, fail_fast=False, **kwargs):
        self.mediator = Mediator(scanners, fail_fast=fail_fast)
        self.fail_fast = fail_fast
        super().__init__(verbose=verbose, **kwargs)

    def start(self) -> ScanStatus:

        has_errors, vf = self.mediator.start()

        return ScanStatus(has_errors, vf.has_vuln)
