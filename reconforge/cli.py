"""reconforge command-line demo."""

from __future__ import annotations

import argparse

from .service import ReconService


def _report(result: dict) -> None:
    print(f"Target: {result['target']}")
    print(f"  assets: {result['asset_count']}  surface score: {result['surface_score']}")
    print(f"  by level: {result['by_level']}")
    print("  highest-exposure assets:")
    for asset in result["assets"][:6]:
        if asset["score"] == 0:
            continue
        print(f"    [{asset['level'].upper():8}] {asset['host']} (score {asset['score']})")
        for f in asset["findings"]:
            print(f"        - [{f['severity']}] {f['reason']}")


def demo() -> None:
    print("1) Aggregating offline recon for a sample target ...")
    print("   (collectors are offline fakes; real adapters need authorization)\n")
    _report(ReconService().assess("example.com"))


def assess(target: str) -> None:
    _report(ReconService().assess(target))


def main() -> None:
    parser = argparse.ArgumentParser(description="reconforge CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="assess a sample target with offline collectors")
    a = sub.add_parser("assess", help="assess one target")
    a.add_argument("target", help="the target domain")
    args = parser.parse_args()
    if args.command == "demo":
        demo()
    elif args.command == "assess":
        assess(args.target)


if __name__ == "__main__":
    main()
