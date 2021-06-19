from typing import List, Dict, Any, Sized

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.scan_results import ScanResults
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_exceptions import NoneResultException


class ScanStatus:

    def __init__(self, has_error=False, has_vulns=False):
        self.has_error = has_error
        self.has_vulns = has_vulns


class MasterScanner(PrintLogger):

    def __init__(self, scanners: List[Scanner], previous_deps: Dict[str, Any] = None, verbose=False, fail_fast=False, **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.mediator = Mediator(scanners, fail_fast=fail_fast)
        self.results = ScanResults(previous_deps, verbose=verbose)
        self.fail_fast = fail_fast
        super().__init__(verbose=verbose, **kwargs)

    def start(self) -> ScanStatus:

        has_errors, vf = self.mediator.start()

        return ScanStatus(has_errors, vf.has_vuln)
