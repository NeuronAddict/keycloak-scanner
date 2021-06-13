from typing import Dict, Any, TypeVar

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.scanner_exceptions import DuplicateResultException
from keycloak_scanner.utils import to_camel_case

T = TypeVar('T')


class ScanResults(PrintLogger):

    def __init__(self, previous_deps: Dict[str, Any] = None, **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.results: Dict[str, Any] = previous_deps
        super().__init__(**kwargs)

    def add(self, name, result: T):
        if name in self.results:
            raise DuplicateResultException(result)
        super().verbose(f'new result with key: {name} ({result})')
        self.results[name] = result

    def __repr__(self):
        return repr(self.results)
