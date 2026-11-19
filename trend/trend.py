#!/usr/bin/env python3
"""Trend test behind the Russia section of "Snowflake on a Pi", part three.

Input: the CSV that Splunk exports for search S5 in that entry, one row per
day with the columns _time, iran, russia, arrivals and elsewhere (iran_share and
russia_share, if present, are ignored and recomputed from the counts).

Six daily series are tested: all arrivals, Iran, Russia and everywhere else as
counts, and Iran's and Russia's share of each day's arrivals. Each series gets a
two-sided Mann-Kendall test (normal approximation with the tie correction and a
continuity correction) and Sen's slope. Because six tests are run at once, the
p-values go through Holm's step-down correction at the chosen level.

The shares are computed from the counts. The export's own share columns are
rounded to 0.1 percentage points, and rounding turns days that differ into ties.

Standard library only:

    python3 trend/trend.py trend/data/s5-2026-10-29_2026-11-15.csv
"""
import argparse
import csv
import math
import statistics
import sys
from collections import Counter

SERIES = [
    ("arrivals", "all arrivals", "count"),
    ("iran", "Iran", "count"),
    ("russia", "Russia", "count"),
    ("elsewhere", "everywhere else", "count"),
    ("iran_share", "Iran's share", "pp"),
    ("russia_share", "Russia's share", "pp"),
]


def mann_kendall(x):
    """Return (S, variance, z, two-sided p) for the series x, in time order."""
    n = len(x)
    if n < 3:
        raise ValueError("Mann-Kendall needs at least three values")
    s = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            d = x[j] - x[i]
            s += (d > 0) - (d < 0)
    ties = Counter(x).values()
    var = (n * (n - 1) * (2 * n + 5) - sum(t * (t - 1) * (2 * t + 5) for t in ties)) / 18
    if s > 0:
        z = (s - 1) / math.sqrt(var)
    elif s < 0:
        z = (s + 1) / math.sqrt(var)
    else:
        z = 0.0
    p = math.erfc(abs(z) / math.sqrt(2))
    return s, var, z, p


def sen_slope(x):
    """Median of the pairwise slopes (x[j] - x[i]) / (j - i), per step."""
    n = len(x)
    return statistics.median((x[j] - x[i]) / (j - i) for i in range(n - 1) for j in range(i + 1, n))


def holm(pvalues, alpha):
    """Holm's step-down procedure.

    Returns, in the input order, (adjusted p-value, rejected?) for each p-value.
    """
    m = len(pvalues)
    order = sorted(range(m), key=lambda k: pvalues[k])
    adjusted = [0.0] * m
    rejected = [False] * m
    running = 0.0
    still = True
    for rank, k in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[k]))
        adjusted[k] = running
        if still and pvalues[k] <= alpha / (m - rank):
            rejected[k] = True
        else:
            still = False
    return list(zip(adjusted, rejected))


def end_share(days, key):
    """A country's share of all arrivals over a run of days, in percent."""
    return 100 * sum(d[key] for d in days) / sum(d["arrivals"] for d in days)


def load(path):
    days = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if not row.get("_time"):
                continue
            iran, russia, arrivals = int(row["iran"]), int(row["russia"]), int(row["arrivals"])
            elsewhere = arrivals - iran - russia
            if "elsewhere" in row and row["elsewhere"] != "" and int(row["elsewhere"]) != elsewhere:
                raise ValueError(f"{row['_time'][:10]}: elsewhere does not equal arrivals - iran - russia")
            days.append({
                "day": row["_time"][:10],
                "arrivals": arrivals,
                "iran": iran,
                "russia": russia,
                "elsewhere": elsewhere,
                "iran_share": 100 * iran / arrivals,
                "russia_share": 100 * russia / arrivals,
            })
    days.sort(key=lambda d: d["day"])
    return days


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv", help="Splunk export of search S5")
    ap.add_argument("--alpha", type=float, default=0.05, help="family-wise level (default 0.05)")
    ap.add_argument("--ends", type=int, default=5,
                    help="days averaged at each end to give the change a size (default 5)")
    a = ap.parse_args(argv)

    days = load(a.csv)
    if len(days) < 2 * a.ends:
        sys.exit(f"trend: {len(days)} days is too few for --ends {a.ends}")
    print(f"{len(days)} days, {days[0]['day']} to {days[-1]['day']}, "
          f"{sum(d['arrivals'] for d in days)} arrivals")
    print()

    results = []
    for key, label, unit in SERIES:
        x = [d[key] for d in days]
        s, var, z, p = mann_kendall(x)
        results.append((key, label, unit, x, s, z, p, sen_slope(x)))
    corrected = holm([r[6] for r in results], a.alpha)

    head = f"{'series':<17}{'S':>5}{'z':>8}{'p':>9}{'Holm p':>9}  {'trend':<6}{'Sen slope per day':>20}"
    print(head)
    print("-" * len(head))
    for (key, label, unit, x, s, z, p, slope), (p_adj, rejected) in zip(results, corrected):
        slope_txt = f"{slope:+.2f} {'pp' if unit == 'pp' else 'arrivals'}"
        print(f"{label:<17}{s:>5}{z:>8.2f}{p:>9.4f}{p_adj:>9.4f}  {'yes' if rejected else 'no':<6}{slope_txt:>20}")
    print()
    print(f"Holm at {a.alpha:g} over {len(results)} tests: 'yes' means the series still looks like a trend.")
    print()

    n = a.ends
    print(f"Share of all arrivals in the first {n} days -> in the last {n} days:")
    for key, label in (("iran", "Iran"), ("russia", "Russia")):
        f, l = end_share(days[:n], key), end_share(days[-n:], key)
        print(f"  {label:<7} {f:5.1f}% -> {l:5.1f}%")


if __name__ == "__main__":
    main()
