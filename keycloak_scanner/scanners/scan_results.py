from typing import Dict, Any, TypeVar, List

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.types import ScannerType
from keycloak_scanner.utils import to_camel_case

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

    def get(self, t: type) -> List[T]:
        return self.results.get(to_camel_case(t.__name__))

    def __repr__(self):
        return repr(self.results)
