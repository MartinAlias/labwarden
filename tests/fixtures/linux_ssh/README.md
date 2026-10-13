Command output used by `tests/test_linux_ssh.py`, one file per allowlisted command.

These were written to match the output formats of `iproute2`, `ss`, `resolvectl` and
`nft -j` on Ubuntu 24.04, not recorded from a live host. The host is shaped like the
planned Docker server: an uplink on VLAN 20, Docker, WireGuard, systemd-resolved and
nftables. MACs use the locally-administered `02:` prefix.
