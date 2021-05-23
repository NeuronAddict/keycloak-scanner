from requests import Session


class SessionHolder:

    def __init__(self, session: Session, **kwargs):
        self.session_ = session
        super().__init__(**kwargs)

    def session(self):
        return self.session_

