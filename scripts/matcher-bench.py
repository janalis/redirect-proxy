#!/usr/bin/env python3
"""Compares the matcher microbenchmark (test/matcher_bench.gleam) with its
baseline, in BEAM reductions per request, which do not depend on the load of
the machine (unlike times).

    scripts/matcher-bench.py           # fail when a scenario costs 10 % more
    scripts/matcher-bench.py --update  # write the current results as baseline

Reductions differ slightly between OTP releases: the baseline is for the
release of .tool-versions, the one CI uses.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "matcher-bench-baseline.json"
TOLERANCE = 0.10


def run():
    out = subprocess.run(
        ["gleam", "run", "-m", "matcher_bench"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout
    line = [l for l in out.splitlines() if l.startswith("{")][-1]
    return json.loads(line)


def main():
    current = run()
    if "--update" in sys.argv[1:]:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE.relative_to(ROOT)}")
        return 0
    baseline = json.loads(BASELINE.read_text())["reductions_per_request"]
    now = current["reductions_per_request"]
    failed = []
    print(f"{'scenario':<24}{'baseline':>10}{'now':>10}{'change':>9}")
    for name in sorted(set(baseline) | set(now)):
        before, after = baseline.get(name), now.get(name)
        if before is None or after is None:
            print(f"{name:<24}{before or '-':>10}{after or '-':>10}")
            continue
        change = (after - before) / before
        mark = ""
        if change > TOLERANCE:
            mark = "  slower"
            failed.append(name)
        elif change < -TOLERANCE:
            mark = "  faster: update the baseline"
        print(f"{name:<24}{before:>10}{after:>10}{change:>+9.0%}{mark}")
    print(f"matcher build ({current['rules']} rules): {current['build_ms']} ms")
    if failed:
        print(f"more than {TOLERANCE:.0%} slower: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
