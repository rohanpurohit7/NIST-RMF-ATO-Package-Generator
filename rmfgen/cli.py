from __future__ import annotations

import argparse
import json

from .core import build_release, run_openscap


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate versioned NIST RMF authorization packages")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--config", required=True)
    build.add_argument("--output", default="releases")

    scap = sub.add_parser("scap")
    scap.add_argument("--content", required=True)
    scap.add_argument("--profile", required=True)
    scap.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "build":
        ctx = build_release(args.config, args.output)
        print(json.dumps({"version": ctx.version, "path": str(ctx.root)}, indent=2))
    elif args.command == "scap":
        print(json.dumps(run_openscap(args.content, args.profile, args.output), indent=2))


if __name__ == "__main__":
    main()
