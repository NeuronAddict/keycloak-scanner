

class RootLogger:

    def info(self, message: str):
        assert not hasattr(super(), 'info')

    def verbose(self, message: str, color: str):
        assert not hasattr(super(), 'verbose')

    def find(self, scanner: str, message: str, color:str):
        assert not hasattr(super(), 'find')

    def warn(self, message: str):
        assert not hasattr(super(), 'warn')
