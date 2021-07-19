from typing import Dict, Any, TypeVar, Set

from keycloak_scanner.logging.printlogger import PrintLogger
from .wrap import WrapperType

T = TypeVar('T')


class ScanResults(PrintLogger):

    def __init__(self, previous_deps: Dict[str, Any] = None, **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.results: Dict[str, Set[Any]] = previous_deps
        super().__init__(**kwargs)

    def add(self, t: WrapperType[T], result: Set[T]):
        if t.name in self.results:
            self.results[t.name] |= result
        else:
            self.results[t.name] = result
        super().verbose(f'new result with key: {t.name} ({result})')

    def get(self, t: WrapperType[T]) -> Set[T]:
        return self.results.get(t.name)

    def __repr__(self):
        return repr(self.results)
