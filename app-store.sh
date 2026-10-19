#!/bin/bash
# pi-app-store: 1
# pi-app-store-category: tools
# pi-app-store-description: Guest WiFi hotspot that clones your current wifi's name. Internet-only for guests, captive splash auto-approves and sends them to google.com. Needs no ethernet: runs the hotspot on the same radio.
set -e
cd "$(dirname "$0")"
case "${1:-run}" in
  run) [ "$#" -eq 0 ] || shift; exec python3 guestwing.py "$@" ;;
  test) python3 -m unittest test_guestwing ;;
  *) echo "usage: $0 [run|test]" >&2; exit 2 ;;
esac
