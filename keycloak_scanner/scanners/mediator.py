from typing import TypeVar, List, Dict, Set

from keycloak_scanner.scanners.scan_results import ScanResults
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.wrap import WrapperType, Wrapper

T = TypeVar('T')


class Mediator:

    def __init__(self, scanners: List[Scanner], **kwargs):
        self.scanners: Dict[str, List[Scanner]] = {}
        self.scan_results = ScanResults()

        for scanner in scanners:
            scanner.set_mediator(self)

        super().__init__(**kwargs)

    def send(self, result_type: WrapperType[T], value_list: Set[T]) -> None:

        self.scan_results.add(result_type, value_list)

        if result_type.name in self.scanners:
            for scanner in self.scanners[result_type.name]:
                for value in value_list:
                    scanner.receive(Wrapper(result_type, value))

    def subscribe(self, scanner, t: WrapperType):
        if t.name in self.scanners:
            self.scanners[t.name].append(scanner)
        else:
            self.scanners[t.name] = [scanner]

