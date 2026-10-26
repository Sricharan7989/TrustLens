import os


class Config:
    def __init__(self, prefix: str = "APP_"):
        self.prefix = prefix
        self.settings = {}

    def load(self) -> dict:
        for k, v in os.environ.items():
            if k.startswith(self.prefix) or k in ("DEBUG", "PORT", "ENV"):
                self.settings[k] = v
        return self.settings


def get_config() -> dict:
    return Config().load()
