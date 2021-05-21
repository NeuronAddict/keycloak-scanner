class MockResponse:

    def __init__(self, status_code, response=None):
        self.status_code = status_code
        self.response = response
        self.text = response

    def json(self):
        if isinstance(self.response, dict):
            return {'response_types_supported': ['code'],
                    'authorization_endpoint': 'http://testscan/auth',
                    'response_modes_supported': ['form_post']
                    }
        else:
            raise Exception(f'response spec is not json ({self.response})')
