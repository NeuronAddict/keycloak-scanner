from typing import TypeVar, List, Dict, Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from .scan_results import ScanResults
from .scanner import Scanner
from .wrap import WrapperType, Wrapper

T = TypeVar('T')


class Mediator:

    def __init__(self, scanners: List[Scanner], initial_values=None, fail_fast=False, **kwargs):

        if initial_values is None:
            initial_values = {}

        self.scanners: Dict[str, List[Scanner]] = {}

        self.initial_values = initial_values

        self.scan_results = ScanResults()
        self.fail_fast = fail_fast

        self.start_scanners = []

        for scanner in scanners:
            if len(scanner.needs) == 0:
                self.start_scanners.append(scanner)
            scanner.set_mediator(self)


        # TODO bad pattern : no conccurency
        self.vuln_flag = VulnFlag(False)

        self.in_progress = False

        self.has_errors = False

        super().__init__(**kwargs)

    def start(self) -> (bool, VulnFlag):
        if not self.in_progress:
            self.in_progress = True

            for wrapper_type, values in self.initial_values.items():

                self.send(wrapper_type, values)

            for scanner in self.start_scanners:
                # TODO : duplicate code
                try:
                    scanner.perform_base()
                except Exception as e:
                    print(f'Failed scan : {scanner.__class__.__name__}: ({str(e)}). ')
                    self.has_errors = True
                    if self.fail_fast:
                        raise e

            self.in_progress = False

            return self.has_errors, self.vuln_flag

        else:
            raise Exception('scan in progress ...')

    def send(self, result_type: WrapperType[T], value_list: Set[T], vuln_flag=VulnFlag(False)) -> None:

        if vuln_flag.has_vuln:
            self.vuln_flag = VulnFlag(True)

        self.scan_results.add(result_type, value_list)

        if result_type.name in self.scanners:

            for scanner in self.scanners[result_type.name]:

                for value in value_list:

                    try:
                        scanner.receive(Wrapper(result_type, value))
                    except Exception as e:
                        print(f'Failed scan : {scanner.__class__.__name__}: ({str(e)}). ')
                        self.has_errors = True
                        if self.fail_fast:
                            raise e

    def subscribe(self, scanner, t: WrapperType):
        if t.name in self.scanners:
            self.scanners[t.name].append(scanner)
        else:
            self.scanners[t.name] = [scanner]

