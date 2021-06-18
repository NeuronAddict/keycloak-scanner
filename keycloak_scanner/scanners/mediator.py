from typing import TypeVar, List, Dict, Any

from keycloak_scanner.scanners.scan_results import ScanResults
from keycloak_scanner.scanners.types import ScannerType
from keycloak_scanner.utils import to_camel_case

T = TypeVar('T')


class Mediator:

    def __init__(self, **kwargs):
        self.scanners: Dict[str, List[Any]] = {}
        self.scan_results = ScanResults()
        super().__init__(**kwargs)

    def send(self, result_type: type, value_list: List[T]) -> None:

        result_type_name = to_camel_case(result_type.__name__)

        self.scan_results.add(result_type_name, value_list)

        if result_type_name in self.scanners:
            for scanner in self.scanners[result_type_name]:
                for value in value_list:
                    scanner.receive(result_type, value)

    def add(self, scanner):
        scanner.set_mediator(self)

    def subscribe(self, scanner, scanner_type_name: str):
        if scanner_type_name in self.scanners:
            self.scanners[scanner_type_name].append(scanner)
        else:
            self.scanners[scanner_type_name] = [scanner]

