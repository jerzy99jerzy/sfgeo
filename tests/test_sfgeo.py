"""Unit tests for sfgeo.py: the capture filter, the GeoIP loader, counting and windows.

Standard library only. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SFGEO = os.path.join(os.path.dirname(HERE), "sfgeo.py")
GEO = os.path.join(HERE, "fixtures", "geoip")


def load_sfgeo():
    """Import sfgeo.py as a module, then put back the exception hooks it installs."""
    saved = sys.excepthook, threading.excepthook
    spec = importlib.util.spec_from_file_location("sfgeo", SFGEO)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.excepthook, threading.excepthook = saved
    return mod


sfgeo = load_sfgeo()


def ip_int(dotted):
    return int.from_bytes(socket.inet_aton(dotted), "big")


def tcpdump_line(src, sport=50112, dst="192.0.2.115", dport=61004):
    """One line as `tcpdump -n -q -t` prints it for an inbound STUN packet."""
    return f"IP {src}.{sport} > {dst}.{dport}: UDP, length 20\n"


def emitted(fn, *args):
    """Run fn and return the JSON lines it printed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args)
    return [json.loads(x) for x in buf.getvalue().splitlines()]


class CaptureFilter(unittest.TestCase):
    def test_filter_is_the_published_one(self):
        self.assertEqual(
            sfgeo.BPF,
            "udp dst portrange 61000-61039 and udp[12:4] = 0x2112a442 "
            "and not src port 19302")

    def test_port_range_matches_the_proxy_flag(self):
        self.assertEqual((sfgeo.PORT_LO, sfgeo.PORT_HI), (61000, 61039))


class GeoLoader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.geo = sfgeo.Geo(GEO)

    def test_ranges_loaded(self):
        self.assertEqual(len(self.geo.lows), 8)

    def test_lookup_inside_and_at_the_edges(self):
        cases = {
            "1.0.0.0": "AU", "1.255.255.255": "AU", "5.6.7.8": "IR",
            "31.0.0.1": "RU", "77.1.2.3": "DE", "192.0.2.7": "IR",
            "198.51.100.200": "RU", "203.0.113.255": "DE",
        }
        for dotted, cc in cases.items():
            with self.subTest(address=dotted):
                self.assertEqual(self.geo.lookup(ip_int(dotted)), cc)

    def test_gaps_and_empty_codes_are_unknown(self):
        for dotted in ("0.255.255.255", "2.0.0.0", "8.8.8.8", "91.1.1.1", "255.255.255.255"):
            with self.subTest(address=dotted):
                self.assertEqual(self.geo.lookup(ip_int(dotted)), "??")

    def test_unsorted_file_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".geoip", delete=False) as fh:
            fh.write("100,200,AA\n50,60,BB\n")
        self.addCleanup(os.unlink, fh.name)
        with self.assertRaises(ValueError):
            sfgeo.Geo(fh.name)

    def test_comments_and_malformed_lines_are_skipped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".geoip", delete=False) as fh:
            fh.write("# comment\n1,2\n10,20,AA\n\n30,40,BB,extra\n")
        self.addCleanup(os.unlink, fh.name)
        geo = sfgeo.Geo(fh.name)
        self.assertEqual(list(geo.lows), [10])
        self.assertEqual(geo.lookup(15), "AA")


class Counting(unittest.TestCase):
    def setUp(self):
        self.state = sfgeo.State(sfgeo.Geo(GEO), 900, 600)

    def test_public_address_counted_under_its_country(self):
        self.state.packet(tcpdump_line("5.6.7.8"))
        self.assertEqual(self.state.cc, {"IR": 1})
        self.assertEqual(self.state.stun_pkts, 1)
        self.assertEqual(len(self.state.seen), 1)

    def test_repeat_within_idle_counts_once(self):
        for _ in range(29):
            self.state.packet(tcpdump_line("31.4.4.4", sport=40000))
        self.assertEqual(self.state.cc, {"RU": 1})
        self.assertEqual(self.state.stun_pkts, 29)

    def test_return_after_idle_counts_again(self):
        t = [1000.0]
        with mock.patch.object(sfgeo.time, "monotonic", lambda: t[0]):
            self.state.packet(tcpdump_line("77.1.1.1"))
            t[0] += 599
            self.state.packet(tcpdump_line("77.1.1.1"))
            t[0] += 601
            self.state.packet(tcpdump_line("77.1.1.1"))
        self.assertEqual(self.state.cc, {"DE": 2})

    def test_nonpublic_sources_are_not_counted(self):
        for dotted in ("0.0.0.1", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1",
                       "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.168.0.10",
                       "224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255"):
            with self.subTest(address=dotted):
                self.state.packet(tcpdump_line(dotted))
        self.assertEqual(self.state.cc, {})
        self.assertEqual(self.state.nonpublic_pkts, 13)
        self.assertEqual(self.state.seen, {})

    def test_edges_of_the_shared_range_are_public(self):
        self.state.packet(tcpdump_line("100.63.255.255"))
        self.state.packet(tcpdump_line("100.128.0.0"))
        self.assertEqual(self.state.nonpublic_pkts, 0)
        self.assertEqual(sum(self.state.cc.values()), 2)

    def test_three_part_address_is_a_parse_error(self):
        # inet_aton would pad "1.2.3" into 1.2.0.3 and count it in some country.
        socket.inet_aton("1.2.3")
        self.state.packet("IP 1.2.3.50112 > 192.0.2.115.61004: UDP, length 20\n")
        self.assertEqual(self.state.parse_err, 1)
        self.assertEqual(self.state.cc, {})

    def test_broken_lines_are_parse_errors(self):
        broken = [
            "IP\n",
            "IP 203.0.113.7 > 192.0.2.115.61004: UDP, length 20\n",
            "IP 203.0.113.256.50112 > 192.0.2.115.61004: UDP, length 20\n",
            "IP 198.51.10\n",
            "IP6 2001:db8::7.50112 > 2001:db8::1.61004: UDP, length 20\n",
            "tcpdump: listening on eth0 203.0.113.9\n",
        ]
        for text in broken:
            self.state.packet(text)
        self.assertEqual(self.state.parse_err, len(broken))
        self.assertEqual(self.state.stun_pkts, len(broken))
        self.assertEqual(self.state.cc, {})

    def test_blank_lines_are_ignored(self):
        for text in ("", "\n", "   \t\n"):
            self.state.packet(text)
        self.assertEqual(self.state.stun_pkts, 0)

    def test_table_holds_24_bit_hashes_only(self):
        for i in range(50):
            self.state.packet(tcpdump_line(f"5.0.{i}.1"))
        self.assertEqual(len(self.state.seen), 50)
        self.assertTrue(all(isinstance(h, bytes) and len(h) == 3 for h in self.state.seen))


class Windows(unittest.TestCase):
    def setUp(self):
        self.state = sfgeo.State(sfgeo.Geo(GEO), 900, 600)

    def test_full_window_has_no_partial_flag(self):
        start = 1_800_000_000
        self.state.win_from = start
        rec, = emitted(self.state.emit, start, start + 900)
        self.assertEqual(rec["covered_s"], 900)
        self.assertNotIn("partial", rec)

    def test_window_seen_in_part_says_so(self):
        start = 1_800_000_000
        self.state.win_from = start + 736
        rec, = emitted(self.state.emit, start, start + 900)
        self.assertEqual(rec["covered_s"], 164)
        self.assertIs(rec["partial"], True)

    def test_start_is_the_window_label(self):
        start = 1_800_000_000
        rec, = emitted(self.state.emit, start, start + 900)
        self.assertRegex(rec["start"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}$")
        self.assertEqual(rec["start"], time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(start)))

    def test_new_clients_is_the_sum_of_countries(self):
        for dotted in ("5.1.1.1", "5.1.1.2", "31.1.1.1", "91.1.1.1", "8.8.4.4"):
            self.state.packet(tcpdump_line(dotted))
        rec, = emitted(self.state.emit, self.state.win_from, self.state.win_from + 900)
        self.assertEqual(rec["cc"], {"??": 2, "IR": 2, "RU": 1})
        self.assertEqual(rec["new_clients"], 5)

    def test_boundary_emits_and_resets(self):
        self.state.packet(tcpdump_line("5.1.1.1"))
        self.state.next_b = int(time.time()) - 1
        recs = emitted(self.state.tick)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["new_clients"], 1)
        self.assertEqual(self.state.cc, {})
        self.assertGreater(self.state.next_b, time.time())
        self.assertEqual(self.state.next_b % 900, 0)

    def test_idle_entries_leave_the_table_at_the_boundary(self):
        self.state.packet(tcpdump_line("5.1.1.1"))
        h, = self.state.seen
        self.state.seen[h] = time.monotonic() - 601
        self.state.next_b = int(time.time()) - 1
        emitted(self.state.tick)
        self.assertEqual(self.state.seen, {})

    def test_key_rotates_with_the_day_and_empties_the_table(self):
        self.state.packet(tcpdump_line("5.1.1.1"))
        old_key = self.state.key
        self.state.key_day = (time.localtime().tm_yday % 366) + 1
        self.state.next_b = int(time.time()) - 1
        emitted(self.state.tick)
        self.assertNotEqual(self.state.key, old_key)
        self.assertEqual(len(self.state.key), 32)
        self.assertEqual(self.state.seen, {})
        self.assertEqual(self.state.key_day, time.localtime().tm_yday)

    def test_same_address_hashes_differently_under_a_new_key(self):
        raw = socket.inet_pton(socket.AF_INET, "5.1.1.1")
        h1 = hmac.new(self.state.key, raw, hashlib.sha256).digest()[:3]
        self.state._rotate_key()
        h2 = hmac.new(self.state.key, raw, hashlib.sha256).digest()[:3]
        self.assertNotEqual(h1, h2)


class SocketCount(unittest.TestCase):
    def test_counts_only_the_proxy_range(self):
        if not os.path.exists("/proc/net/udp"):
            self.skipTest("no /proc/net/udp here")
        before = sfgeo.count_sockets()
        socks = []
        try:
            for port in (60999, 61000, 61039, 61040):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                socks.append(s)
                try:
                    s.bind(("127.0.0.1", port))
                except OSError:
                    self.skipTest(f"port {port} is taken on this machine")
            self.assertEqual(sfgeo.count_sockets() - before, 2)
        finally:
            for s in socks:
                s.close()


if __name__ == "__main__":
    unittest.main()
