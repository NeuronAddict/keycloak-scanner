from keycloak_scanner.logging.printlogger import PrintLogger


class MockResponse:

    def __init__(self, status_code, response=None):
        self.status_code = status_code
        self.response = response
        self.text = response

    def raise_for_status(self):
        if self.status_code > 399:
            raise Exception('Mock raise for status')

    def json(self):
        if isinstance(self.response, dict):
            return self.response
        else:
            raise Exception(f'response spec is not json ({self.response})')


class MockPrintLogger(PrintLogger):

    def __init__(self, **kwargs):
        self.infos = []
        self.verboses = []
        self.warns = []
        super().__init__(**kwargs)

    def info(self, message: str):
        self.infos.append(message)
        super().info(message)

    def verbose(self, message: str, color='grey'):
        self.verboses.append({'message': message, 'color': color})
        super().verbose(message, color)

    def warn(self, message: str):
        self.warns.append(message)
        super().warn(message)
