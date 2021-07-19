

class VoidFlag:

    def __init__(self, **kwargs):
        self.has_vuln = False
        super().__init__(**kwargs)

    def set_vuln(self):
        assert not hasattr(super(), 'set_vuln')


class VulnFlag(VoidFlag):

    def __init__(self, has_vuln=False, **kwargs):
        super().__init__(**kwargs)
        self.has_vuln = has_vuln

    def set_vuln(self):
        self.has_vuln = True
        super().set_vuln()
