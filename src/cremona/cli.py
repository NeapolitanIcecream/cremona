from __future__ import annotations

import argparse

from . import scan as scan_module


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cremona")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("scan",),
        help="Command to run.",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the selected command.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return scan_module.main(args.args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
