# sfgeo

Counts a Snowflake proxy's users per country without keeping their addresses.

sfgeo runs next to a [Snowflake](https://snowflake.torproject.org/) proxy and reads only the packets that open each user's connection: the inbound STUN connectivity checks. It looks up each source address in a local GeoIP file, counts it and forgets it. Every fifteen minutes it writes one line of counts to the journal. No address, and no hash of one, reaches its output, its error messages, the disk or the network.

It is the counter behind the country figures in *Snowflake on a Raspberry Pi*. [Part two](https://www.handsomeboyscomputer.club/log/snowflake-on-a-pi-2/) explains the method and what a proxy operator can and cannot protect; [part three](https://www.handsomeboyscomputer.club/log/snowflake-on-a-pi-3/) uses its first eighteen days, and the trend test in [`trend/`](trend/) is the one behind that entry's section on Russia.

Python standard library only, one file, IPv4 only.

## How it counts

A kernel filter hands sfgeo nothing but the STUN packets arriving at the proxy's WebRTC port range:

```sh
tcpdump -n -l -q -t -p -Q in -i eth0 \
  'udp dst portrange 61000-61039 and udp[12:4] = 0x2112a442 and not src port 19302'
```

Every STUN message carries the magic cookie `0x2112A442` four bytes into its header, which is twelve bytes into the UDP datagram. `not src port 19302` drops the answers from the public STUN server the proxy itself uses (Google's, by default). The relayed traffic never leaves the kernel, so on a single-core Pi the capture costs next to nothing.

For each packet sfgeo:

1. drops private, shared (CGNAT), loopback, link-local, multicast and reserved source addresses;
2. computes an HMAC-SHA256 of the address with a random 32-byte key that exists only in memory and is replaced every day, and keeps 24 bits of it, enough to tell a returning address from a new one;
3. if the address has been silent for more than ten minutes, counts a new arrival and looks up its country;
4. drops the address.

Windows are aligned to the clock (:00, :15, :30, :45). At each boundary it prints one line, empties the counters and forgets hashes that have been silent for ten minutes; the whole table goes when the key changes. A real line from the Pi, the first window after a restart, seen for 164 of its 900 seconds:

```json
{"v":1,"start":"2026-10-28T23:30:00+0100","window_s":900,"covered_s":164,"new_clients":0,"cc":{},"stun_pkts":0,"nonpublic_pkts":0,"parse_err":0,"sock_max":2,"sock_avg":0.2,"sock_samples":17,"tracked":0,"partial":true}
```

| field | meaning |
|---|---|
| `start` | the window's label, local time |
| `window_s`, `covered_s` | the window's length, and how much of it this process saw |
| `partial` | present, and true, when `covered_s` is less than the window: the first window after a start, the last before a stop |
| `new_clients` | arrivals: addresses seen for the first time, or again after ten minutes of silence |
| `cc` | arrivals per country code; `??` is an address the GeoIP file has no country for |
| `stun_pkts` | non-blank lines read from the capture |
| `nonpublic_pkts`, `parse_err` | packets from non-public sources, and lines that did not parse; both should stay at zero |
| `sock_max`, `sock_avg`, `sock_samples` | UDP sockets open in the proxy's port range, sampled every ten seconds; no addresses involved |
| `tracked` | hashes in the table when the line was written |

An arrival is an address, not a person. Many users behind one carrier-grade NAT address count once, and a user on a VPN counts in the VPN's country. Part two goes through what that means for the numbers.

## Why nothing is left

The rule sfgeo is built around is that an address must never reach a disk, a log line, a third party or a crash dump, and that nothing it writes is small and precise enough to point at one person by itself.

- **The key is the protection.** The 24-bit truncation alone does not protect much: someone who holds the key and the table and has a list of candidate addresses can hash the candidates and look for matches. What protects the table is that the key and the table exist only in the running process, and the key is replaced daily. Anyone who can read that memory can run the capture directly. (The module's docstring still describes the truncation in the older terms; it is left as deployed, so that the file stays byte-identical with the one that produced the published numbers.)
- **Errors print their type and nothing else.** A traceback can quote the line it failed on, and that line holds an address. Once packets flow, sfgeo prints only the exception's type, for the main program and for its timer thread, and sends tcpdump's own messages to `/dev/null`. The one message with contents is a GeoIP file that fails to load at start, before the first packet.
- **`inet_pton`, not `inet_aton`.** `inet_aton` accepts `1.2.3` and pads it into a full address, so a truncated capture line would be counted in some random country.
- **No crash dumps.** The unit sets `LimitCORE=0`; a core file would be a copy of memory with addresses in it.
- **No lookups leave the box.** The GeoIP file is Tor's own, read from disk.

"Forgets" means dropped, not wiped: Python cannot overwrite memory it has freed, so until it is reused an address can still be read by whoever can read the process's memory, which is root, who can run the capture anyway.

## Checking it yourself

```sh
python3 -m unittest discover -s tests -v
```

Python 3.11 or newer, no packages, about twenty seconds. The same tests run in CI on every push.

[`tests/test_privacy.py`](tests/test_privacy.py) is the privacy invariant as a test. It starts `sfgeo.py` the way systemd does, with the capture replaced by stdin, and feeds it made-up tcpdump lines: hundreds of random public addresses from the whole IPv4 space, private and reserved ones, and broken lines of every shape a capture or a cut pipe can produce. It cuts the input off in the middle of a window, stops sfgeo with SIGTERM in the middle of a window, sends bytes that are not text, and gives it a GeoIP file that does not load. Then it searches everything sfgeo wrote, on stdout and on stderr, for every address it was fed, in dotted, decimal, hexadecimal and raw form, and for anything with three dot-separated runs of digits. It fails if it finds one. It also fails if a line carries any field outside sfgeo's known output, so a new field cannot slip an address past the search, and it checks the counts against what was sent, so a run that silently dropped its input would not pass.

[`tests/test_sfgeo.py`](tests/test_sfgeo.py) covers the filter, the GeoIP loader, counting, windows and the daily key change.

On a running box the journal is the place to look:

```sh
journalctl -u sfgeo -o cat | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

prints nothing if sfgeo has kept its rule (the start line's version number has only two dots).

## Running it

You need Linux with systemd, Python 3.11 or newer, tcpdump, and a `snowflake-proxy` started with `-ephemeral-ports-range 61000:61039`. The range is a constant at the top of `sfgeo.py` (`PORT_LO`, `PORT_HI`, and the filter in `BPF`); change both if your proxy uses another.

The GeoIP file comes from Debian's `tor-geoipdb`. The package depends on `tor`, and the Tor daemon is not needed for this, so extract the file without installing the package:

```sh
cd /tmp && apt-get download tor-geoipdb
dpkg-deb -x tor-geoipdb_*.deb /tmp/tgdb
sudo install -D -m 0644 /tmp/tgdb/usr/share/tor/geoip /usr/local/share/sfgeo/geoip
```

Then install the program and the unit, and start it:

```sh
sudo install -D -m 0644 sfgeo.py /usr/local/lib/sfgeo/sfgeo.py
sudo install -m 0644 systemd/sfgeo.service /etc/systemd/system/sfgeo.service
sudo systemctl daemon-reload
sudo systemctl enable --now sfgeo.service
journalctl -u sfgeo -f -o cat
```

The first line is `{"v":1,"event":"start",...}` with the number of GeoIP ranges loaded; on a Raspberry Pi 1 loading takes about 24 seconds. The unit reads from `eth0`; edit `--iface` in `ExecStart` if your interface is called something else.

[`systemd/sfgeo.service`](systemd/sfgeo.service) gives the service a dynamic user and one capability, `CAP_NET_RAW`, which is all a capture with `-p` (no promiscuous mode) needs. Its `MemoryMax=64M` is enforced only if the kernel has the memory controller: `cat /sys/fs/cgroup/cgroup.controllers` must list `memory`, and `systemctl show -p MemoryCurrent sfgeo` must return a number. systemd stores the limit either way and prints it back when asked.

| option | default | |
|---|---|---|
| `--geo` | `/usr/local/share/sfgeo/geoip` | GeoIP file in Tor's format (`INTIPLOW,INTIPHIGH,CC`, sorted) |
| `--iface` | `eth0` | interface to capture on |
| `--window` | `900` | window length in seconds |
| `--sample` | `10` | seconds between socket samples and boundary checks |
| `--idle` | `600` | seconds of silence after which an address counts as a new arrival |
| `--stdin` | off | read tcpdump-format lines from stdin instead of starting tcpdump (tests) |

## The version behind the published numbers

sfgeo 0.1.2 produced every country figure in parts two and three. It has run on the Pi since 28 October 2026, and on 16 November the deployed file had this hash:

```
cb11a2694ceaa06535206e9055dfcbe903afa6c08afd645702e5e83041092723  sfgeo.py
```

`sfgeo.py` here, at tag `v0.1.2`, is that file byte for byte. The unit's directives are the deployed ones; only its header comment was rewritten, because the deployed one named the host. `grep -v '^#' systemd/sfgeo.service | sha256sum` gives `2e43d09f6ba910ec502982966eab865437dd2c46caf1cf085b9c456ea662464b` for both.

## The trend test

[`trend/trend.py`](trend/trend.py) is the test behind the section on Russia in part three, and [`trend/data/`](trend/data/) holds the daily numbers it ran on: search S5 from that entry, exported from Splunk as it came, one row per day from 29 October to 15 November 2026. Daily totals only, nothing finer.

```sh
python3 trend/trend.py trend/data/s5-2026-10-29_2026-11-15.csv
```

```
18 days, 2026-10-29 to 2026-11-15, 4151 arrivals

series               S       z        p   Holm p  trend    Sen slope per day
----------------------------------------------------------------------------
all arrivals        24    0.87   0.3833   0.3833  no          +1.00 arrivals
Iran                55    2.05   0.0408   0.1633  no          +2.00 arrivals
Russia             -63   -2.36   0.0182   0.0912  no          -1.10 arrivals
everywhere else     40    1.48   0.1388   0.2775  no          +0.75 arrivals
Iran's share        55    2.05   0.0408   0.1633  no                +0.40 pp
Russia's share     -79   -2.95   0.0031   0.0188  yes               -0.76 pp

Holm at 0.05 over 6 tests: 'yes' means the series still looks like a trend.

Share of all arrivals in the first 5 days -> in the last 5 days:
  Iran     50.2% ->  56.4%
  Russia   29.1% ->  20.2%
```

Each of the six daily series gets a two-sided [Mann-Kendall test](https://doi.org/10.2307/1907187) (normal approximation, with the tie and continuity corrections) and Sen's slope, and the six p-values go through [Holm's correction](https://www.jstor.org/stable/4615733). The shares are computed from the counts; the export's own share columns are rounded to 0.1 points, and rounding turns days that differ into ties. Standard library only; the implementation was checked against [pymannkendall](https://github.com/mmhs013/pymannkendall) and statsmodels, and `tests/test_trend.py` pins the published result to the data.

## Security

See [SECURITY.md](SECURITY.md). A way for sfgeo to write, keep or send an address is the bug that matters most here.

## License

[MIT](LICENSE).
