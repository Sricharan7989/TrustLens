import os


def parse_ssh_config(config_path: str = "~/.ssh/config") -> dict:
    resolved = os.path.expanduser(config_path)
    hosts = {}
    if os.path.exists(resolved):
        try:
            with open(resolved, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0].lower() == "host":
                        hosts[parts[1]] = {}
        except Exception:
            pass
    return hosts
