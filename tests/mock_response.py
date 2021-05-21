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
