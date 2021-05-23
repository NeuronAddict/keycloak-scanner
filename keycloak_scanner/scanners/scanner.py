from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.session_holder import SessionHolder


class Scanner(SessionHolder, PrintLogger):

    def __init__(self, base_url: str, **kwargs):
        self.base_url_ = base_url
        super().__init__(**kwargs)

    def base_url(self):
        assert not hasattr(super(), 'base_url')
        return self.base_url_

    def name(self):
        assert not hasattr(super(), 'name')
        return self.__class__.__name__

    def init_scan(self):
        super().info(f'Start logger {self.name()}')
        assert not hasattr(super(), 'init_scan')

    def perform(self, scan_properties):
        """
        Perform the scan
        :return: scan result (json)
        """
        assert not hasattr(super(), 'perform')
