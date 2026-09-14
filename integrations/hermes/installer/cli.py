from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .core import InstallOptions, InstallerError, lifecycle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lifedb-hermes-installer")
    parser.add_argument("--hermes-home", required=True, type=Path)
    parser.add_argument("command", choices=("check", "install", "disable", "enable", "uninstall"))
    parser.add_argument("--url", default="http://127.0.0.1:7331")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    parser.add_argument("--max-response-bytes", type=int, default=1_048_576)
    parser.add_argument("--max-request-bytes", type=int, default=4_194_304)
    parser.add_argument("--sensitivity-ceiling")
    parser.add_argument("--budget-chars", type=int, default=12_000)
    parser.add_argument("--core-chars", type=int, default=4_000)
    parser.add_argument("--continuity-chars", type=int, default=2_000)
    parser.add_argument("--relevant-chars", type=int, default=6_000)
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args(argv)
    if args.command == "install" and args.token_file is None:
        parser.error("--token-file is required for install")
    token_file = args.token_file or Path("/")
    options = InstallOptions(args.url, token_file, args.workspace, args.timeout_seconds, args.max_response_bytes, args.max_request_bytes, args.sensitivity_ceiling, args.budget_chars, args.core_chars, args.continuity_chars, args.relevant_chars, args.limit)
    try:
        lifecycle(args.hermes_home, args.command, options)
    except InstallerError:
        print("Hermes installer operation failed", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
