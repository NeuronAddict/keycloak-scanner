from requests import Session


class SessionHolder:

    def __init__(self, session: Session):
        self.session_ = session

    def session(self):
        return self.session_

