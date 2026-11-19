# Security

The bug that matters most in sfgeo is any way for it to write, keep or send an address it has seen: in its output, in an error message, in a crash, in a file, or through anything else that outlives the packet. Weaknesses in the filter or the counting that could make the published numbers wrong are worth reporting too.

Please report privately, not in a public issue:

- on GitHub, from this repository's **Security** tab, with **Report a vulnerability**;
- or through the contact listed in [security.txt](https://www.handsomeboyscomputer.club/.well-known/security.txt), which links a PGP key.

A test that reproduces the problem, in the style of [`tests/test_privacy.py`](tests/test_privacy.py), helps most.

Supported: the latest tagged version.
