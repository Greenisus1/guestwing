#!/bin/bash
# guestwing installer: deps + files, then run. curl -sSL https://raw.githubusercontent.com/Greenisus1/guestwing/main/install.sh | bash
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo: curl -sSL https://raw.githubusercontent.com/Greenisus1/guestwing/main/install.sh | sudo bash"; exit 1; }
apt-get update -qq
apt-get install -y -qq hostapd dnsmasq ipset iw wireless-tools iptables python3
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
