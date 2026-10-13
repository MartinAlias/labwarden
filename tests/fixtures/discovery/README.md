Command output used by `tests/test_discovery.py`: `/proc/net/arp`, `arp -a` on Windows, `arp -an` on macOS, and an `nmap -oX` report.

These were written to match each tool's format, not recorded from a live network. The
addresses follow the user's current flat LAN (`192.168.4.0/24`). MACs use the
locally-administered `02:` prefix.
