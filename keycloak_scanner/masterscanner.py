import re
from typing import List, Dict, Any

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.scanner import Scanner


def to_camel_case(text: str):
    return re.sub('([a-z]+)([A-Z])', r'\1_\2', text).lower()


class DuplicateResultException(Exception):
    pass


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


class NoneResultException(Exception):
    pass


class MasterScanner(PrintLogger):

    def __init__(self, scans: List[Scanner], previous_deps: Dict[str, Any] = None, verbose=False, **kwargs):
        if previous_deps is None:
            previous_deps = {}
        self.scans = scans
        self.results = ScanResults(previous_deps, verbose=verbose)
        super().__init__(verbose=verbose, **kwargs)

    def start(self):

        # TODO: return code when error
        for scanner in self.scans:

            try:
                result = scanner.perform(**self.results.results)

                if result is None:
                    super().warn(f'None result for scanner {scanner.name()}')
                    raise NoneResultException()

                if hasattr(result, '__len__') and len(result) == 0:
                    super().warn(f'Result of {scanner.name()} as no results (void list), subsequent scans can be void too.')
                self.results.add(result)

            except TypeError as e:
                print(f'Missing dependency for {scanner.__class__.__name__}: ({str(e)}). '
                      f'A required previous scanner as fail.')

            except Exception as e:
                print(f'Failed scan : {scanner.__class__.__name__}: ({str(e)}). ')
