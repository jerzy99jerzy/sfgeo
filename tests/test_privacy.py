"""The privacy invariant, as a test anyone can run.

sfgeo is started the way systemd starts it (python3 -I), with its capture
replaced by stdin (--stdin), and fed made-up tcpdump lines: public addresses
drawn from the whole IPv4 space, private and reserved ones, and broken lines of
the shapes a capture or a cut pipe can produce. Everything it writes, on stdout
(what reaches the journal) and on stderr, is then searched for addresses.

The test fails if a single address, or anything shaped like one, appears in
that output, in four runs:

- input cut off in the middle of a window (the capture ends);
- SIGTERM in the middle of a window (systemctl stop or restart);
- bytes that are not text, inside and around addresses;
- a GeoIP file that does not load, before any packet is read.

A fifth test raises an exception whose message holds an address and checks
that sfgeo's last-resort handlers, for the main program and for its timer
thread, print the exception's type and nothing else.

It also fails if a line on stdout carries any field outside sfgeo's known
output, so a new field cannot slip an address past the search. The counts in
the output are checked against what was sent, which shows that the lines were
read and classified, not dropped unseen.

Standard library only. Run from the repository root:

    python3 -m unittest discover -s tests -v

The addresses are random; SFGEO_TEST_SEED=<int> repeats a run.
"""
import ipaddress
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SFGEO = os.path.join(os.path.dirname(HERE), "sfgeo.py")
GEO = os.path.join(HERE, "fixtures", "geoip")

WINDOW = 2
SAMPLE = 1
SEED = int(os.environ.get("SFGEO_TEST_SEED", random.SystemRandom().randrange(1 << 31)))

NONPUBLIC = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]

START_KEYS = {"v", "event", "version", "geo_ranges", "geo_load_s", "window_s", "idle_s"}
WINDOW_KEYS = {"v", "start", "window_s", "covered_s", "new_clients", "cc", "stun_pkts",
               "nonpublic_pkts", "parse_err", "sock_max", "sock_avg", "sock_samples", "tracked"}
INT_FIELDS = WINDOW_KEYS - {"start", "cc", "sock_avg"}
STDERR_OK = [re.compile(p) for p in (
    r"sfgeo: input ended \(tcpdump rc=0\)",
    r"sfgeo: fatal [A-Za-z_][A-Za-z0-9_]*",
    r"sfgeo: thread fatal [A-Za-z_][A-Za-z0-9_]*",
)]
GEO_FAIL = re.compile(r"sfgeo: geoip load failed: [A-Za-z]+Error: .*")

# Anything with three dot-separated runs of digits: a full address, or the
# first three octets of one. Float fields have one dot at most.
DOTTED = re.compile(r"(?<![0-9])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])")


def is_public(ip):
    return not any(ip in n for n in NONPUBLIC)


def line(src, sport, dst="192.0.2.115", dport=61004):
    return f"IP {src}.{sport} > {dst}.{dport}: UDP, length 20\n"


class Workload:
    """Made-up input with the counts sfgeo should report for it."""

    def __init__(self, rng):
        self.addresses = set()
        public = []
        while len(public) < 400:
            ip = ipaddress.IPv4Address(rng.getrandbits(32))
            if is_public(ip) and ip not in public:
                public.append(ip)
        for doc in ("192.0.2.7", "198.51.100.23", "203.0.113.42"):
            ip = ipaddress.IPv4Address(doc)
            if ip not in public:
                public.append(ip)
        private = []
        for net in NONPUBLIC:
            for _ in range(5):
                lo = int(net.network_address)
                private.append(ipaddress.IPv4Address(lo + rng.randrange(net.num_addresses)))
        self.addresses.update(public)
        self.addresses.update(private)

        def sport():
            p = rng.randrange(1024, 65536)
            return 19303 if p == 19302 else p

        first = [line(ip, sport()) for ip in public]
        repeats = [line(ip, sport()) for ip in rng.sample(public, 120)]
        privates = [line(ip, sport()) for ip in private]
        a, b, c = public[0], public[1], public[2]
        broken = [
            "IP\n",
            f"IP {a}\n",
            f"IP {a} > 192.0.2.115.61004: UDP, length 20\n",
            f"IP {'.'.join(str(a).split('.')[:3])}.{sport()} > 192.0.2.115.61004: UDP, length 20\n",
            f"IP {'.'.join(str(b).split('.')[:3])}.256.{sport()} > 192.0.2.115.61004: UDP, length 20\n",
            f"IP {'.'.join(str(c).split('.')[:2])}\n",
            f"IP6 2001:db8::{rng.randrange(1, 9999):x}.{sport()} > 2001:db8::1.61004: UDP, length 20\n",
            f"tcpdump: listening on eth0, {a} {b} {c}\n",
            f"{a}.{sport()} > 192.0.2.115.61004: UDP, length 20\n",
            "IP " + "9" * 4096 + "\n",
            f"IP {int(a)}.{sport()} > 192.0.2.115.61004: UDP, length 20\n",
            f"IP 0x{int(b):08x}.{sport()} > 192.0.2.115.61004: UDP, length 20\n",
        ]
        blanks = ["\n", "   \n", "\t\n"]
        body = first + repeats + privates + broken + blanks
        rng.shuffle(body)
        # Every first sighting has to come before its repeats, or a repeat is the new one.
        seen, ordered, later = set(), [], []
        for text in body:
            src = text.split()[1] if text.startswith("IP ") and len(text.split()) > 1 else None
            key = src.rsplit(".", 1)[0] if src else None
            if text in repeats and key not in seen:
                later.append(text)
                continue
            if key:
                seen.add(key)
            ordered.append(text)
        self.lines = ordered + later
        self.expect = {
            "stun_pkts": len(first) + len(repeats) + len(privates) + len(broken),
            "nonpublic_pkts": len(privates),
            "parse_err": len(broken),
            "new_clients": len(public),
        }


class Run:
    """sfgeo in --stdin mode, with its output collected as bytes."""

    def __init__(self, geo=GEO):
        self.out, self.err = [], []
        self.started = threading.Event()
        self.p = subprocess.Popen(
            [sys.executable, "-I", SFGEO, "--stdin", "--geo", geo,
             "--window", str(WINDOW), "--sample", str(SAMPLE)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.readers = [threading.Thread(target=self._read, args=(self.p.stdout, self.out, True)),
                        threading.Thread(target=self._read, args=(self.p.stderr, self.err, False))]
        for t in self.readers:
            t.start()

    def _read(self, stream, sink, is_stdout):
        for raw in iter(stream.readline, b""):
            sink.append(raw)
            if is_stdout and b'"event":"start"' in raw:
                self.started.set()

    def send(self, texts, spread_s):
        pause = spread_s / max(len(texts), 1)
        for text in texts:
            self.p.stdin.write(text.encode("ascii"))
            self.p.stdin.flush()
            time.sleep(pause)

    def finish(self, timeout=30):
        rc = self.p.wait(timeout=timeout)
        for t in self.readers:
            t.join(timeout)
        self.p.stdout.close()
        self.p.stderr.close()
        return rc


def mid_window():
    """Sleep until the middle of the current wall-clock window."""
    phase = time.time() % WINDOW
    time.sleep((WINDOW / 2 - phase) % WINDOW)


class PrivacyInvariant(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(SEED)
        self.work = Workload(self.rng)

    def assert_no_address(self, run, addresses):
        blob = b"".join(run.out + run.err)
        text = blob.decode("utf-8", "replace")
        text = re.sub(r'"version":"[0-9.]+"', '"version":""', text)
        msg = f"(SFGEO_TEST_SEED={SEED})"
        self.assertIsNone(DOTTED.search(text), f"dotted address-like run in output {msg}")
        for ip in addresses:
            for form in (str(ip), str(int(ip)), f"{int(ip):08x}", f"{int(ip):08X}"):
                self.assertNotIn(form, text, f"address {ip} written as {form!r} {msg}")
            self.assertNotIn(ip.packed, blob, f"address {ip} written as raw bytes {msg}")

    def assert_known_output(self, run):
        start, windows = None, []
        for raw in run.out:
            rec = json.loads(raw)
            self.assertIsInstance(rec, dict)
            if rec.get("event") == "start":
                self.assertEqual(set(rec), START_KEYS)
                self.assertIsNone(start, "two start lines")
                start = rec
                continue
            keys = set(rec)
            self.assertTrue(WINDOW_KEYS <= keys <= WINDOW_KEYS | {"partial"}, sorted(keys))
            for k in INT_FIELDS:
                self.assertIs(type(rec[k]), int, k)
            self.assertTrue(rec["sock_avg"] is None or type(rec["sock_avg"]) in (int, float))
            self.assertRegex(rec["start"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}$")
            for cc, n in rec["cc"].items():
                self.assertRegex(cc, r"^[A-Z?]{2}$")
                self.assertIs(type(n), int)
            self.assertEqual(sum(rec["cc"].values()), rec["new_clients"])
            if "partial" in rec:
                self.assertIs(rec["partial"], True)
                self.assertLess(rec["covered_s"], rec["window_s"])
            else:
                self.assertEqual(rec["covered_s"], rec["window_s"])
            windows.append(rec)
        for raw in run.err:
            msg = raw.decode("ascii").rstrip("\n")
            self.assertTrue(any(p.fullmatch(msg) for p in STDERR_OK), f"unexpected stderr: {msg!r}")
        self.assertIsNotNone(start)
        return windows

    def assert_counts(self, windows):
        for field, want in self.work.expect.items():
            got = sum(w[field] for w in windows)
            if field == "new_clients":
                # Two addresses can share a 24-bit hash and count once: with about
                # 400 addresses that happens in roughly one run in two hundred.
                self.assertIn(want - got, (0, 1, 2), f"{field}: {got} of {want} (SFGEO_TEST_SEED={SEED})")
            else:
                self.assertEqual(got, want, f"{field} (SFGEO_TEST_SEED={SEED})")

    def started_run(self):
        run = Run()
        self.assertTrue(run.started.wait(30), "sfgeo did not start")
        return run

    def test_input_cut_off_mid_window(self):
        run = self.started_run()
        run.send(self.work.lines, spread_s=2.5 * WINDOW)
        mid_window()
        run.p.stdin.close()
        self.assertEqual(run.finish(), 0)
        windows = self.assert_known_output(run)
        self.assertGreaterEqual(len(windows), 2)
        self.assertIs(windows[-1].get("partial"), True)
        self.assert_counts(windows)
        self.assert_no_address(run, self.work.addresses)

    def test_sigterm_mid_window(self):
        run = self.started_run()
        run.send(self.work.lines, spread_s=2.5 * WINDOW)
        mid_window()
        run.p.send_signal(signal.SIGTERM)
        self.assertEqual(run.finish(), 0)
        run.p.stdin.close()
        windows = self.assert_known_output(run)
        self.assertIs(windows[-1].get("partial"), True)
        self.assertEqual(run.err, [], "a clean stop writes nothing to stderr")
        self.assert_counts(windows)
        self.assert_no_address(run, self.work.addresses)

    def test_undecodable_bytes_do_not_leak(self):
        run = self.started_run()
        half = len(self.work.lines) // 2
        run.send(self.work.lines[:half], spread_s=WINDOW)
        a, b = sorted(self.work.addresses)[:2]
        a3 = ".".join(str(a).split(".")[:3]).encode()
        bad = [
            b"IP " + str(a).encode() + b".5000 \xff\xfe > 192.0.2.115.61004: UDP, length 20\n",
            b"IP " + a3 + b".\xff.5000 > 192.0.2.115.61004: UDP, length 20\n",
            b"IP \xc3\x28" + str(b).encode() + b".5000 > 192.0.2.115.61004\n",
            b"\x00\x01\x02 " + str(b).encode() + b"\n",
        ]
        for raw in bad:
            run.p.stdin.write(raw)
        run.p.stdin.flush()
        run.send(self.work.lines[half:], spread_s=WINDOW)
        mid_window()
        try:
            run.p.stdin.close()
        except BrokenPipeError:
            pass
        rc = run.finish()
        errs = [e.rstrip(b"\n") for e in run.err]
        # Python reads stdin with surrogateescape, so the bytes arrive as text and the
        # lines count as packets or parse errors. Where decoding is strict, sfgeo dies
        # on them instead, and then the fatal line is the only thing it may print.
        self.assertIn((rc, errs), [(0, [b"sfgeo: input ended (tcpdump rc=0)"]),
                                    (1, [b"sfgeo: fatal UnicodeDecodeError"])])
        self.assert_known_output(run)
        self.assert_no_address(run, self.work.addresses)

    def test_fatal_errors_print_the_type_only(self):
        import importlib.util
        import io
        from unittest import mock
        saved = sys.excepthook, threading.excepthook
        spec = importlib.util.spec_from_file_location("sfgeo_hooks", SFGEO)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            hook, thread_hook = sys.excepthook, threading.excepthook
        finally:
            sys.excepthook, threading.excepthook = saved
        ip = sorted(self.work.addresses)[0]
        exc = ValueError(f"bad packet from {ip}.5000")
        err = io.StringIO()
        with mock.patch.object(mod.sys, "stderr", err):
            hook(type(exc), exc, None)
        self.assertEqual(err.getvalue(), "sfgeo: fatal ValueError\n")
        err = io.StringIO()
        args = threading.ExceptHookArgs((type(exc), exc, None, None))
        with mock.patch.object(mod.sys, "stderr", err), \
                mock.patch.object(mod.os, "_exit") as exit_:
            thread_hook(args)
        self.assertEqual(err.getvalue(), "sfgeo: thread fatal ValueError\n")
        exit_.assert_called_once_with(1)

    def test_geoip_failure_writes_only_the_load_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".geoip", delete=False) as fh:
            fh.write("200,300,AA\n100,150,BB\n")
        self.addCleanup(os.unlink, fh.name)
        run = Run(geo=fh.name)
        try:
            run.send(self.work.lines[:50], spread_s=0.2)
        except BrokenPipeError:
            pass
        rc = run.finish()
        try:
            run.p.stdin.close()
        except BrokenPipeError:
            pass
        self.assertEqual(rc, 2)
        self.assertEqual(run.out, [])
        self.assertEqual(len(run.err), 1)
        self.assertRegex(run.err[0].decode("ascii").rstrip("\n"), GEO_FAIL)
        self.assert_no_address(run, self.work.addresses)


if __name__ == "__main__":
    unittest.main()
