#!/bin/sh
# LabWarden SSH forced command.
#
# authorized_keys forces every login with the labwarden key to run this
# script. Whatever command the client asked for arrives in
# $SSH_ORIGINAL_COMMAND, and only the exact lines below are run. Nothing is
# eval'd and no arguments are passed through, so the client can't change what
# runs.
#
# This list must match COMMANDS in src/labwarden/collectors/linux_ssh.py
# (tests/test_linux_ssh.py checks it).
set -eu

case "${SSH_ORIGINAL_COMMAND:-}" in
  "ip -d -j addr")               exec ip -d -j addr ;;
  "ip -j route")                 exec ip -j route ;;
  "ip -j -6 route")              exec ip -j -6 route ;;
  "ss -H -tulpn")                exec ss -H -tulpn ;;
  "cat /etc/os-release")         exec cat /etc/os-release ;;
  "cat /etc/resolv.conf")        exec cat /etc/resolv.conf ;;
  "resolvectl dns")              exec resolvectl dns ;;
  "sudo -n nft -j list ruleset") exec sudo -n nft -j list ruleset ;;
  *)
    if command -v logger >/dev/null 2>&1; then
      logger -t labwarden-ssh -- "refused command: ${SSH_ORIGINAL_COMMAND:-<interactive login>}"
    fi
    echo "labwarden: command not allowed" >&2
    exit 126
    ;;
esac
