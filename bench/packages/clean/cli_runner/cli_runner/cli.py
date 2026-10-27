import sys
from cli_runner import run_command


def main() -> int:
    args = sys.argv[1:] or ["echo", "hello"]
    print(run_command(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
