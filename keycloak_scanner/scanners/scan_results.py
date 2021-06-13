from typing import Dict, Any

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.scanner_exceptions import DuplicateResultException
from keycloak_scanner.utils import to_camel_case


class ScanResults(PrintLogger):

    def __init__(self, previous_deps: Dict[str, Any], **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.results: Dict[str, Any] = previous_deps
        super().__init__(**kwargs)

    def add(self, result: Any):
        key = to_camel_case(result.__class__.__name__)
        if key in self.results:
            raise DuplicateResultException(result)
        super().verbose(f'new result with key: {key} ({result})')
        self.results[key] = result

    def __repr__(self):
        return repr(self.results)