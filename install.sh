#!/bin/bash
# guestwing installer: deps + files, then run. curl -sSL https://raw.githubusercontent.com/Greenisus1/guestwing/main/install.sh | bash
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo: curl -sSL https://raw.githubusercontent.com/Greenisus1/guestwing/main/install.sh | sudo bash"; exit 1; }
PRE=0
systemctl is-active --quiet dnsmasq 2>/dev/null && PRE=1
apt-get update -qq
apt-get install -y -qq hostapd dnsmasq ipset iw wireless-tools iptables python3
if [ "$PRE" = 0 ]; then
  # apt auto-started a system dnsmasq on port 53; we run our own per-hotspot one
  systemctl stop dnsmasq 2>/dev/null || true
  systemctl disable dnsmasq 2>/dev/null || true
else
  echo "note: a system dnsmasq was already running; guestwing's own dnsmasq binds only the hotspot interface"
fi
mkdir -p /opt/guestwing
B=https://raw.githubusercontent.com/Greenisus1/guestwing/main
for f in guestwing.py test_guestwing.py app-store.sh app-version.json LICENSE README.md; do
  curl -sSL "$B/$f" -o "/opt/guestwing/$f"
done
chmod +x /opt/guestwing/app-store.sh
cat > /usr/local/bin/guestwing <<'SH'
#!/bin/bash
exec python3 /opt/guestwing/guestwing.py "$@"
SH
chmod +x /usr/local/bin/guestwing
echo "guestwing installed. Run it with: guestwing"
