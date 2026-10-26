import subprocess


def run_command(cmd: list[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return res.stdout.strip()
