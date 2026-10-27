import uuid

NAMESPACE_DNS = uuid.NAMESPACE_DNS


def make_id(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE_DNS, name))


def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except ValueError:
        return False
