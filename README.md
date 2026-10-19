# guestwing

Guest WiFi hotspot for a Raspberry Pi (DietPi or any Debian). The guest network is named **pi wifi** by default (rename it in the app or with `--ssid`), and it clones your current WiFi's WPA2 password when one is found, so anyone who already knows your wifi password can join - but guests get **internet only**: they can't see or touch anything on your LAN.

When a guest connects, their phone pops the captive splash instantly, approves them automatically, and sends them to google.com. No buttons, no passwords page.

**No ethernet needed.** The hotspot runs on the same wifi radio as your existing connection (client + AP on one radio, same channel). A USB wifi adapter works too if your radio refuses.

## Run

```
guestwing
```

(or `bash app-store.sh` from the store). It re-execs with sudo; hostapd, dnsmasq, ipset and friends auto-install.

- Press `n` to set a custom hotspot name (default: `pi wifi`; or start with `guestwing --ssid "my name"`).
- Press `s` twice to start. First press shows exactly what will happen: the clone SSID and channel. Your own connection is never reconfigured.
- Press `s` again to stop. Stopping tears down hostapd/dnsmasq and restores iptables from a snapshot taken at start.
- `q` quits; if the hotspot is running it asks twice, then stops everything.

## How it works

- Adds a virtual AP interface (`wlan0_ap`) on your existing radio and broadcasts the guest network (name `pi wifi` or your custom one; your current wifi's WPA2 password when found in wpa_supplicant.conf, open otherwise).
- Guests land on 192.168.50.0/24. dnsmasq hands out DHCP + DNS; hostapd runs the AP.
- Until a guest is approved, their web traffic is redirected to the built-in captive portal; the first hit approves them (ipset) and 302s to https://www.google.com. Phones open the splash on their own via the usual probe URLs.
- iptables drops all guest traffic toward private address space (10/8, 172.16/12, 192.168/16, 169.254/16) - guests can only reach the internet, NATed out your existing connection.
- Kernel and your own network config are never modified. The radio stays on the channel your wifi already uses, so if your router hops channels, stop and start the hotspot to follow.

## Safety

Nothing changes until you press `s` twice. `guestwing --dry-run` prints the exact hostapd/dnsmasq/iptables config without touching anything. Stopping always restores the pre-start iptables snapshot.

MIT, Greenisus1. Built with AI assistance from my design.
