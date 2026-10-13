#!/bin/sh
# LabWarden SSH forced command.
#
# authorized_keys forces every login with the labwarden key to run this
# script. Whatever command the client asked for arrives in
# $SSH_ORIGINAL_COMMAND. Nothing is ever eval'd. Two kinds of command run:
#
# 1. Collector commands: exact lines, no arguments. These must match COMMANDS
#    in src/labwarden/collectors/linux_ssh.py (tests/test_linux_ssh.py checks).
# 2. Probes (ping, traceroute, dig, nc, curl): the line is split on spaces
#    (globbing off), and every argument is checked by position before exec.
#    These must match REMOTE_PATTERNS in src/labwarden/probes/execution.py
#    (tests/test_probes.py runs both against the same inputs).
set -eu

refuse() {
  if command -v logger >/dev/null 2>&1; then
    logger -t labwarden-ssh -- "refused command: ${SSH_ORIGINAL_COMMAND:-<interactive login>}"
  fi
  echo "labwarden: command not allowed" >&2
  exit 126
}

# --- argument checks for probes ------------------------------------------------

# A decimal number from $2 to $3, without leading zeros.
in_range() {
  case "$1" in ''|0*|*[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 5 ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}
# Host name or IP. Must not start with "-", so it can never be read as an option.
is_host() {
  case "$1" in ''|-*|*[!A-Za-z0-9.:-]*) return 1 ;; esac
  [ "${#1}" -le 253 ]
}
is_dns_name() {
  case "$1" in ''|-*|.*|*[!A-Za-z0-9._-]*) return 1 ;; esac
  [ "${#1}" -le 253 ]
}
is_dns_server() {
  case "$1" in @*) is_host "${1#@}" ;; *) return 1 ;; esac
}
is_record_type() {
  case "$1" in A|AAAA|CNAME|MX|TXT|NS|PTR|SOA|SRV) return 0 ;; *) return 1 ;; esac
}
is_url() {
  case "$1" in http://?*|https://?*) ;; *) return 1 ;; esac
  case "$1" in *[!A-Za-z0-9.:/%+=_-]*) return 1 ;; esac
  rest="${1#*://}"
  [ "${#rest}" -le 2000 ]
}

probe() {
  set -f        # no globbing of the split words
  IFS=' '
  # shellcheck disable=SC2086  # splitting is the point; nothing is evaluated
  set -- ${SSH_ORIGINAL_COMMAND:-}
  case "${1:-}" in
    ping)
      [ "$#" -eq 7 ] && [ "$2" = -c ] && in_range "$3" 1 5 && [ "$4" = -W ] \
        && in_range "$5" 1 5 && [ "$6" = -n ] && is_host "$7" \
        && exec ping -c "$3" -W "$5" -n "$7" ;;
    traceroute)
      [ "$#" -eq 9 ] && [ "$2" = -n ] && [ "$3" = -q ] && [ "$4" = 1 ] && [ "$5" = -w ] \
        && [ "$6" = 2 ] && [ "$7" = -m ] && in_range "$8" 1 30 && is_host "$9" \
        && exec traceroute -n -q 1 -w 2 -m "$8" "$9" ;;
    dig)
      [ "$#" -ge 8 ] && [ "$2" = +time=2 ] && [ "$3" = +tries=1 ] && [ "$4" = +noall ] \
        && [ "$5" = +comments ] && [ "$6" = +answer ] || return 1
      if [ "$#" -eq 8 ]; then
        is_dns_name "$7" && is_record_type "$8" \
          && exec dig +time=2 +tries=1 +noall +comments +answer "$7" "$8"
      elif [ "$#" -eq 9 ]; then
        is_dns_server "$7" && is_dns_name "$8" && is_record_type "$9" \
          && exec dig +time=2 +tries=1 +noall +comments +answer "$7" "$8" "$9"
      fi ;;
    nc)
      [ "$#" -eq 6 ] && [ "$2" = -z ] && [ "$3" = -w ] && in_range "$4" 1 9 \
        && is_host "$5" && in_range "$6" 1 65535 \
        && exec nc -z -w "$4" "$5" "$6" ;;
    curl)
      [ "$#" -eq 6 ] && [ "$2" = -sS ] && [ "$3" = -I ] && [ "$4" = -m ] \
        && in_range "$5" 1 30 && is_url "$6" \
        && exec curl -sS -I -m "$5" "$6" ;;
  esac
  return 1
}

# --- dispatch --------------------------------------------------------------------

case "${SSH_ORIGINAL_COMMAND:-}" in
  "ip -d -j addr")               exec ip -d -j addr ;;
  "ip -j route")                 exec ip -j route ;;
  "ip -j -6 route")              exec ip -j -6 route ;;
  "ss -H -tulpn")                exec ss -H -tulpn ;;
  "cat /etc/os-release")         exec cat /etc/os-release ;;
  "cat /etc/resolv.conf")        exec cat /etc/resolv.conf ;;
  "resolvectl dns")              exec resolvectl dns ;;
  "sudo -n nft -j list ruleset") exec sudo -n nft -j list ruleset ;;
  *)                             probe || refuse ;;
esac
refuse
