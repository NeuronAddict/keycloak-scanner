from typing import TypeVar, List, Dict, Any

from keycloak_scanner.scanners.scan_results import ScanResults
from keycloak_scanner.scanners.wrap import WrapperType

T = TypeVar('T')


class Mediator:

    def __init__(self, **kwargs):
        self.scanners: Dict[str, List[Any]] = {}
        self.scan_results = ScanResults()
        super().__init__(**kwargs)

    def send(self, result_type: WrapperType[T], value_list: List[T]) -> None:

        self.scan_results.add(result_type, value_list)

        if result_type.name in self.scanners:
            for scanner in self.scanners[result_type.name]:
                for value in value_list:
                    scanner.receive(result_type, value)

    def add(self, scanner):
        scanner.set_mediator(self)

    def subscribe(self, scanner, t: WrapperType):
        if t.name in self.scanners:
            self.scanners[t.name].append(scanner)
        else:
            self.scanners[t.name] = [scanner]

