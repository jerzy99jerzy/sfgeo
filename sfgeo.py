#!/usr/bin/env python3
"""sfgeo 0.1.2 - per-country Snowflake client counts from inbound ICE/STUN packets.

Data path: tcpdump (cBPF filter in the kernel: inbound UDP to the proxy's ICE
range carrying the STUN magic cookie) -> pipe -> this process.

Address handling: a client IPv4 address exists only in this process's memory.
It is mapped to a country (Tor's geoip file, extracted from tor-geoipdb
without installing tor) and to a 24-bit keyed hash
used for de-duplication, then the reference is dropped. Nothing containing an
address is written to stdout, stderr or disk: exceptions are reported by type
name only, tcpdump's stderr goes to /dev/null. The hash key lives in RAM only
and rotates daily; 24 bits means each stored value maps to ~256 IPv4 addresses
even if key and table were both dumped. Python cannot wipe freed strings, so
"dropped" means unreferenced, not zeroed.

Output: one JSON line per wall-clock-aligned window on stdout (journald).
"start" labels the window; "covered_s" is how much of it this process saw,
and "partial" marks a window seen for less than all of it (the first after a
start, the last before a stop).
"""
import argparse
import array
import bisect
import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

VERSION = "0.1.2"
PORT_LO, PORT_HI = 61000, 61039
BPF = (f"udp dst portrange {PORT_LO}-{PORT_HI} "
       "and udp[12:4] = 0x2112a442 and not src port 19302")
NONPUBLIC = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
             "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
             "224.0.0.0/4", "240.0.0.0/4"]


def _quiet_hook(exc_type, exc, tb):
    sys.stderr.write(f"sfgeo: fatal {exc_type.__name__}\n")


def _term(signum, frame):
    raise SystemExit(0)


def _quiet_thread_hook(args):
    sys.stderr.write(f"sfgeo: thread fatal {args.exc_type.__name__}\n")
    os._exit(1)


sys.excepthook = _quiet_hook
threading.excepthook = _quiet_thread_hook


def cidr_ranges(cidrs):
    out = []
    for c in cidrs:
        net, bits = c.split("/")
        lo = int.from_bytes(socket.inet_aton(net), "big")
        out.append((lo, lo + (1 << (32 - int(bits))) - 1))
    return out


class Geo:
    """Tor geoip format: INTIPLOW,INTIPHIGH,CC per line, sorted, '#' comments."""

    def __init__(self, path):
        t0 = time.monotonic()
        self.lows = array.array("I")
        self.highs = array.array("I")
        self.idx = array.array("H")
        self.codes = []
        code_ix = {}
        prev = -1
        with open(path, encoding="ascii") as fh:
            for line in fh:
                if not line or line[0] == "#":
                    continue
                parts = line.strip().split(",")
                if len(parts) != 3:
                    continue
                lo, hi, cc = int(parts[0]), int(parts[1]), parts[2] or "??"
                if lo < prev:
                    raise ValueError("geoip not sorted")
                prev = lo
                if cc not in code_ix:
                    code_ix[cc] = len(self.codes)
                    self.codes.append(cc)
                self.lows.append(lo)
                self.highs.append(hi)
                self.idx.append(code_ix[cc])
        self.load_s = round(time.monotonic() - t0, 1)

    def lookup(self, ip):
        i = bisect.bisect_right(self.lows, ip) - 1
        if i >= 0 and ip <= self.highs[i]:
            return self.codes[self.idx[i]]
        return "??"


def count_sockets():
    n = 0
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path) as fh:
                next(fh)
                for line in fh:
                    port = int(line.split()[1].rsplit(":", 1)[1], 16)
                    if PORT_LO <= port <= PORT_HI:
                        n += 1
        except (OSError, StopIteration, ValueError, IndexError):
            pass
    return n


class State:
    def __init__(self, geo, window, idle):
        self.geo, self.window, self.idle = geo, window, idle
        self.nonpublic = cidr_ranges(NONPUBLIC)
        self.lock = threading.Lock()
        self.seen = {}
        self._rotate_key()
        self._reset()
        self.win_from = time.time()
        self.next_b = (int(self.win_from) // window + 1) * window

    def _rotate_key(self):
        self.key = os.urandom(32)
        self.key_day = time.localtime().tm_yday
        self.seen.clear()

    def _reset(self):
        self.cc = {}
        self.stun_pkts = 0
        self.nonpublic_pkts = 0
        self.parse_err = 0
        self.sock_max = 0
        self.sock_sum = 0
        self.sock_n = 0

    def _is_nonpublic(self, ip):
        return any(lo <= ip <= hi for lo, hi in self.nonpublic)

    def packet(self, line):
        parts = line.split()
        if not parts:
            return
        with self.lock:
            self.stun_pkts += 1
            if len(parts) < 2 or parts[0] != "IP":
                self.parse_err += 1
                return
            try:
                raw = socket.inet_pton(socket.AF_INET, parts[1].rsplit(".", 1)[0])
            except OSError:
                self.parse_err += 1
                return
            ip = int.from_bytes(raw, "big")
            if self._is_nonpublic(ip):
                self.nonpublic_pkts += 1
                return
            h = hmac.new(self.key, raw, hashlib.sha256).digest()[:3]
            now = time.monotonic()
            last = self.seen.get(h)
            self.seen[h] = now
            if last is None or now - last > self.idle:
                c = self.geo.lookup(ip)
                self.cc[c] = self.cc.get(c, 0) + 1
            del raw, ip, parts

    def sample(self):
        n = count_sockets()
        with self.lock:
            self.sock_max = max(self.sock_max, n)
            self.sock_sum += n
            self.sock_n += 1

    def emit(self, start, end):
        covered = int(end - max(start, self.win_from))
        rec = {
            "v": 1,
            "start": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(start)),
            "window_s": self.window,
            "covered_s": covered,
            "new_clients": sum(self.cc.values()),
            "cc": dict(sorted(self.cc.items())),
            "stun_pkts": self.stun_pkts,
            "nonpublic_pkts": self.nonpublic_pkts,
            "parse_err": self.parse_err,
            "sock_max": self.sock_max,
            "sock_avg": round(self.sock_sum / self.sock_n, 1) if self.sock_n else None,
            "sock_samples": self.sock_n,
            "tracked": len(self.seen),
        }
        if covered < self.window:
            rec["partial"] = True
        print(json.dumps(rec, separators=(",", ":")), flush=True)

    def tick(self):
        now = time.time()
        with self.lock:
            while now >= self.next_b:
                self.emit(self.next_b - self.window, self.next_b)
                self._reset()
                self.win_from = self.next_b
                cutoff = time.monotonic() - self.idle
                for h in [h for h, t in self.seen.items() if t < cutoff]:
                    del self.seen[h]
                if time.localtime().tm_yday != self.key_day:
                    self._rotate_key()
                self.next_b = (int(now) // self.window + 1) * self.window


def ticker(state, interval, stop):
    while not stop.wait(interval):
        state.sample()
        state.tick()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--geo", default="/usr/local/share/sfgeo/geoip")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--window", type=int, default=900)
    ap.add_argument("--sample", type=int, default=10)
    ap.add_argument("--idle", type=int, default=600)
    ap.add_argument("--stdin", action="store_true",
                    help="test mode: read tcpdump-format lines from stdin")
    a = ap.parse_args()

    try:
        geo = Geo(a.geo)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"sfgeo: geoip load failed: {type(e).__name__}: {e}\n")
        sys.exit(2)
    state = State(geo, a.window, a.idle)
    print(json.dumps({"v": 1, "event": "start", "version": VERSION,
                      "geo_ranges": len(geo.lows), "geo_load_s": geo.load_s,
                      "window_s": a.window, "idle_s": a.idle},
                     separators=(",", ":")), flush=True)

    stop = threading.Event()
    threading.Thread(target=ticker, args=(state, a.sample, stop), daemon=True).start()

    if a.stdin:
        src, proc = sys.stdin, None
    else:
        proc = subprocess.Popen(
            ["tcpdump", "-n", "-l", "-q", "-t", "-p", "-Q", "in", "-i", a.iface, BPF],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        src = proc.stdout

    signal.signal(signal.SIGTERM, _term)
    try:
        for line in src:
            try:
                state.packet(line)
            except Exception:
                with state.lock:
                    state.parse_err += 1
            line = None
    finally:
        stop.set()
        with state.lock:
            state.emit(state.next_b - state.window, time.time())
    rc = proc.wait() if proc else 0
    sys.stderr.write(f"sfgeo: input ended (tcpdump rc={rc})\n")
    sys.exit(1 if proc else 0)


if __name__ == "__main__":
    main()
