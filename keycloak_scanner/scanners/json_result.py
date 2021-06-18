import json


class JsonResult:

    def __init__(self, name: str, url: str, json: dict):
        self.name = name
        self.url = url
        self.json = json

    def __repr__(self):
        return f"{self.__class__.__name__}('{self.name}', '{self.url}', {self.json})"

    def __hash__(self):
        return hash((self.name, self.url, json.dumps(self.json)))

    def __eq__(self, other):
        if isinstance(other, JsonResult):
            return self.name == other.name and self.url == other.url and self.json == other.json
        return NotImplemented