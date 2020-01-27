from abc import ABC, abstractmethod


class Scan(ABC):

    def __init__(self):
        self.scan_properties = {}

    def init(self, config, scan_properties):
        self.scan_properties = scan_properties

    @abstractmethod
    def perform(self, launch_properties, scan_properties):
        """

        :return: scan result (json)
        """
        pass


