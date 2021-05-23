import re
from typing import List, Dict, Any

from keycloak_scanner.scanners.scanner import Scanner


def to_camel_case(text: str):
    return re.sub('([a-z]+)([A-Z])', r'\1_\2', text).lower()


class MasterScanner:

    def __init__(self, scans: List[Scanner], previous_deps=None):
        if previous_deps is None:
            previous_deps = {}
        self.scans = scans
        self.previous_deps = previous_deps

    def start(self):

        results = self.previous_deps

        for scanner in self.scans:
            try:
                result = scanner.perform(**results)
                results[result.__class__.__name__] = result
            except TypeError as e:
                print(f'Missing dependency for {scanner.__class__.__name__}: ({repr(e)}). '
                      f'A required previous scanner as fail.')
            except Exception as e:
                print(f'Failed scan : {scanner.__class__.__name__}: ({repr(e)}). ')
