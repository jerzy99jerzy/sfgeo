# Changelog

## Repository, 2026-11-19

- Published: `sfgeo.py` 0.1.2 as deployed, its systemd unit, the privacy invariant test and unit tests, and the trend test from part three of *Snowflake on a Raspberry Pi* with the daily numbers it ran on.

## 0.1.2, 2026-10-28

- Catches SIGTERM and writes the window in progress, marked `partial`, before it exits. Before this, `systemctl restart` lost that window.

## 0.1.1, 2026-10-28

- Each line carries `covered_s`, how many seconds of its window the process saw, and `partial` when that is less than the whole window. Before this, the first window after a start was silently undercounted.

## 0.1.0, 2026-10-28

- First version: counts per country from inbound STUN packets in 15-minute windows, addresses held in memory only, a daily key for the 24-bit hashes.
