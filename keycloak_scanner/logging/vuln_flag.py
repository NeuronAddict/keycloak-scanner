

class VoidFlag:

    def __init__(self, **kwargs):
        self.has_vuln = False
        super().__init__(**kwargs)

    def set_vuln(self):
        raise NotImplemented()


class VulnFlag(VoidFlag):

    def __init__(self, **kwargs):
        self.has_vuln = False
        super().__init__(**kwargs)

    def set_vuln(self):
        self.has_vuln = True
        super().set_vuln(True)
