import re


def to_camel_case(text: str):
    return re.sub('([a-z]+)([A-Z])', r'\1_\2', text).lower()
