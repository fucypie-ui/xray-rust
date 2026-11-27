"""Run a Linux Rust gate and reject empty or silently ignored test filters."""

import argparse
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filter")
    parser.add_argument("minimum", type=int)
    parser.add_argument("--test", dest="integration", metavar="NAME", help="Run one integration target instead of the library")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ignored", action="store_true")
    mode.add_argument("--include-ignored", action="store_true")
    args = parser.parse_args()
    if args.minimum < 1:
        parser.error("minimum must be positive")
    if args.integration is not None and not args.integration:
        parser.error("--test NAME must not be empty")
    target = ["--test", args.integration] if args.integration is not None else ["--lib"]
    command = [
        "cargo", "test", "--locked", *target, args.filter,
        "--", "--nocapture", "--test-threads=1",
    ]
    if args.ignored:
        command.append("--ignored")
    if args.include_ignored:
        command.append("--include-ignored")
    summaries = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as child:
        for line in child.stdout:
            print(line, end="", flush=True)
            plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
            match = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", plain)
            if match:
                summaries.append(tuple(map(int, match.groups())))
        result = child.wait()
    if result:
        return result
    if len(summaries) != 1:
        raise SystemExit(f"Required one test summary for {args.filter!r}; got {summaries!r}")
    passed, failed, ignored = summaries[0]
    if passed < args.minimum or failed or ignored:
        raise SystemExit(
            f"Required at least {args.minimum} passing tests and no failures/ignores for "
            f"{args.filter!r}; got passed={passed}, failed={failed}, ignored={ignored}"
        )
    print(f"Required gate passed: {args.filter} ({passed} executed tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
