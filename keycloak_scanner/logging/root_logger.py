

class RootLogger:

    def info(self, message: str):
        assert not hasattr(super(), 'info')

    def verbose(self, message: str, color: str):
        assert not hasattr(super(), 'verbose')

