import json


def parse_payload(payload: str) -> dict:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


def dump_payload(data: dict) -> str:
    return json.dumps(data, sort_keys=True)
