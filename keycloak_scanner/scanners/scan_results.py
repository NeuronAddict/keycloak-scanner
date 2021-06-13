from typing import Dict, Any, TypeVar, List

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.types import ScannerType

T = TypeVar('T')


class ScanResults(PrintLogger):

    def __init__(self, previous_deps: Dict[str, Any] = None, **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.results: Dict[str, List[Any]] = previous_deps
        super().__init__(**kwargs)

    def add(self, name, result: List[T]):
        if name in self.results:
            self.results[name] += result
        else:
            self.results[name] = result
        super().verbose(f'new result with key: {name} ({result})')

    def get(self, t: ScannerType[T]) -> T:
        return self.results.get(t.name)

    def __repr__(self):
        return repr(self.results)
