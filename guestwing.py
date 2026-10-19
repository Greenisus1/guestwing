#!/usr/bin/env python3
"""guestwing - guest WiFi hotspot with an instant-approve captive portal.

Makes an open-to-join guest network that only reaches the internet: clients
are isolated from your LAN, a captive splash opens the moment they connect,
approves them instantly, and sends them to google.com.

Clones your current WiFi's name (and password, if found) so joining feels
familiar. Runs its own hostapd + dnsmasq + iptables; everything is torn down
and restored on stop. Needs root; re-execs with sudo. Dry-run: --dry-run.

MIT, Greenisus1. Built with AI assistance from my design.
"""
import curses, ipaddress, json, os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time, urllib.parse

VERSION = '1.2.1'
GUEST_NET = ipaddress.ip_network('192.168.50.0/24')
AP_IP = '192.168.50.1'
DHCP_LO, DHCP_HI = '192.168.50.100', '192.168.50.200'
DEFAULT_SSID = 'pi wifi'
DEFAULT_PSK = '12345678'
PORTAL_PORT = 8080
HIJACK_DNS_PORT = 5353
IPSET = 'guestwing_ok'
STATE_DIR = os.environ.get('GW_STATE') or '/run/guestwing'
LEASES = os.path.join(STATE_DIR, 'dnsmasq.leases')
PIDFILE = os.path.join(STATE_DIR, 'pids.json')
SNAPSHOT = os.path.join(STATE_DIR, 'iptables.snapshot')
PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']
DEPS = ['hostapd', 'dnsmasq', 'ipset', 'iw', 'iwgetid', 'iptables']
PROBE_PATHS = ('hotspot-detect', 'generate_204', 'gen_204', 'connecttest', 'ncsi',
               'canonical', 'success', 'check_network_status', 'redirect', 'library/test')

# ---------------------------------------------------------------- run helper
class Runner:
    """Executes privileged commands; dry_run records instead."""
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.planned = []
    def __call__(self, *args, ok_rc=(0,)):
        cmd = [str(a) for a in args]
        if self.dry_run:
            self.planned.append(cmd)
            return ''
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode not in ok_rc:
            raise RuntimeError('failed: %s\n%s' % (' '.join(cmd), p.stderr.strip()))
        return p.stdout

def out(*args):
    try:
        return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ''

# ---------------------------------------------------------------- detection
def interfaces():
    return sorted(d for d in os.listdir('/sys/class/net') if d != 'lo')

def is_wireless(iface):
    return os.path.isdir('/sys/class/net/%s/wireless' % iface)

def default_route_ifaces():
    return re.findall(r'^default .* dev (\S+)', out('ip', 'route', 'show', 'default'), re.M)

def has_carrier(iface):
    try:
        return open('/sys/class/net/%s/carrier' % iface).read().strip() == '1'
    except Exception:
        return False

def current_ssid():
    s = out('iwgetid', '-r').strip()
    return s or None

def wifi_credentials(ssid):
    """Find the PSK for ssid from wpa_supplicant configs (DietPi keeps wifi there)."""
    cands = ['/etc/wpa_supplicant/wpa_supplicant.conf'] + \
            [os.path.join('/etc/wpa_supplicant', f) for f in os.listdir('/etc/wpa_supplicant')] \
            if os.path.isdir('/etc/wpa_supplicant') else []
    for path in dict.fromkeys(cands):
        try:
            text = open(path).read()
        except Exception:
            continue
        creds = parse_wpa_conf(text)
        if ssid in creds:
            return creds[ssid]
    return None

def parse_wpa_conf(text):
    """Extract {ssid: psk-or-None} from wpa_supplicant.conf text (testable)."""
    creds = {}
    for block in re.findall(r'network\s*=\s*\{(.*?)\}', text, re.S):
        m = re.search(r'ssid\s*=\s*"([^"]+)"', block)
        if not m:
            continue
        p = re.search(r'psk\s*=\s*"([^"]+)"', block)
        km = re.search(r'key_mgmt\s*=\s*(\S+)', block)
        creds[m.group(1)] = p.group(1) if p else (None if km and 'NONE' in km.group(1) else None)
    return creds

def sta_channel(iface):
    """(channel, hw_mode) of the iface's current association, from iw link."""
    m = re.search(r'freq:\s*(\d+)', out('iw', 'dev', iface, 'link'))
    if not m:
        return None, None
    f = int(m.group(1))
    if f < 3000:
        return (f - 2407) // 5, 'g'
    return (f - 5000) // 5, 'a'

def plan_interfaces():
    """Clone mode: uplink = the interface carrying the default route (his
    current wifi, untouched); hotspot = a virtual AP interface on the SAME
    radio. Returns (uplink, base_radio, ap_iface, warning)."""
    ifaces = interfaces()
    wifi = [i for i in ifaces if is_wireless(i)]
    routes = default_route_ifaces()
    uplink = routes[0] if routes else None
    if not uplink:
        return None, None, None, 'no internet connection found - connect to wifi first, then rerun'
    base = uplink if uplink in wifi else (wifi[0] if wifi else None)
    if not base:
        return uplink, None, None, 'no wireless interface found to host the hotspot'
    if uplink == base:
        ch, mode = sta_channel(base)
        if not ch:
            return uplink, base, None, 'could not read the current wifi channel - is %s connected?' % base
        return uplink, base, base + '_ap', None
    return uplink, base, base + '_ap', None

# ---------------------------------------------------------------- config gen
def hostapd_conf(iface, ssid, psk, channel=6, hw_mode='g'):
    lines = ['interface=%s' % iface, 'driver=nl80211', 'ssid=%s' % ssid,
             'hw_mode=%s' % hw_mode, 'channel=%d' % channel, 'ieee80211n=1',
             'wmm_enabled=1', 'auth_algs=1', 'ignore_broadcast_ssid=0']
    if psk:
        lines += ['wpa=2', 'wpa_passphrase=%s' % psk, 'wpa_key_mgmt=WPA-PSK',
                  'rsn_pairwise=CCMP']
    return '\n'.join(lines) + '\n'

def dnsmasq_conf(iface):
    return '\n'.join([
        'interface=%s' % iface, 'bind-interfaces', 'domain-needed', 'bogus-priv',
        'dhcp-range=%s,%s,255.255.255.0,12h' % (DHCP_LO, DHCP_HI),
        'dhcp-option=3,%s' % AP_IP, 'dhcp-option=6,%s' % AP_IP,
        'dhcp-leasefile=%s' % LEASES, 'log-dhcp', 'pid-file=%s' % os.path.join(STATE_DIR, 'dnsmasq.pid'),
    ]) + '\n'

def iptables_script(ap, uplink):
    """Shell script body applying the full ruleset (testable string)."""
    return '\n'.join([
        'set -e',
        'ipset create %s hash:ip -exist' % IPSET,
        'iptables -t nat -N GW_CAP 2>/dev/null || iptables -t nat -F GW_CAP',
        'iptables -t nat -A GW_CAP -p tcp --dport 80 -m set ! --match-set %s src -j REDIRECT --to-ports %d' % (IPSET, PORTAL_PORT),
        'iptables -t nat -A GW_CAP -p udp --dport 53 -m set ! --match-set %s src -j REDIRECT --to-ports %d' % (IPSET, HIJACK_DNS_PORT),
        'iptables -t nat -A GW_CAP -p tcp --dport 53 -m set ! --match-set %s src -j REDIRECT --to-ports %d' % (IPSET, HIJACK_DNS_PORT),
        'iptables -t nat -C PREROUTING -i %s -j GW_CAP 2>/dev/null || iptables -t nat -A PREROUTING -i %s -j GW_CAP' % (ap, ap),
        'iptables -N GW_FWD 2>/dev/null || iptables -F GW_FWD',
        'iptables -A GW_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
        'iptables -A GW_FWD -i %s -m set ! --match-set %s src -j DROP' % (ap, IPSET),
        'iptables -A GW_FWD -i %s -d 10.0.0.0/8 -j DROP' % ap,
        'iptables -A GW_FWD -i %s -d 172.16.0.0/12 -j DROP' % ap,
        'iptables -A GW_FWD -i %s -d 192.168.0.0/16 -j DROP' % ap,
        'iptables -A GW_FWD -i %s -d 169.254.0.0/16 -j DROP' % ap,
        'iptables -A GW_FWD -i %s -o %s -j ACCEPT' % (ap, uplink),
        'iptables -C FORWARD -j GW_FWD 2>/dev/null || iptables -A FORWARD -j GW_FWD',
        'iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE' % (GUEST_NET, uplink, GUEST_NET, uplink),
        'sysctl -w net.ipv4.ip_forward=1 >/dev/null',
    ]) + '\n'

def teardown_script(ap):
    return '\n'.join([
        'iptables -t nat -D PREROUTING -i %s -j GW_CAP 2>/dev/null || true' % ap,
        'iptables -t nat -F GW_CAP 2>/dev/null || true',
        'iptables -t nat -X GW_CAP 2>/dev/null || true',
        'iptables -D FORWARD -j GW_FWD 2>/dev/null || true',
        'iptables -F GW_FWD 2>/dev/null || true',
        'iptables -X GW_FWD 2>/dev/null || true',
        "iptables-save | grep -v 'GW_CAP\\|GW_FWD\\|%s' | iptables-restore || true" % IPSET,
        'ipset destroy %s 2>/dev/null || true' % IPSET,
    ]) + '\n'

# ---------------------------------------------------------------- hijack DNS
def dns_answer(packet, ip):
    """Build a DNS response mapping every A/AAAA query to ip (testable)."""
    if len(packet) < 12:
        return None
    tid, flags, qd = struct.unpack('>HHH', packet[:6])
    if qd == 0:
        return None
    i = 12
    while i < len(packet) and packet[i] != 0:
        i += packet[i] + 1
    i += 5  # null + qtype(2) + qclass(2)
    question = packet[12:i]
    answer = struct.pack('>HHHLH', 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    return struct.pack('>HHHHHH', tid, 0x8180, 1, 1, 0, 0) + question + answer

class HijackDNS(threading.Thread):
    def __init__(self, bind_ip, port, answer_ip):
        super().__init__(daemon=True)
        self.bind_ip, self.port, self.answer_ip = bind_ip, port, answer_ip
        self.sock = None
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_ip, self.port))
        self.sock = s
        while True:
            try:
                data, addr = s.recvfrom(512)
            except OSError:
                return
            resp = dns_answer(data, self.answer_ip)
            if resp:
                try:
                    s.sendto(resp, addr)
                except OSError:
                    return
    def stop(self):
        if self.sock:
            self.sock.close()

# ---------------------------------------------------------------- portal
class Portal(threading.Thread):
    """HTTP portal: any request auto-approves the source IP and 302s to google."""
    def __init__(self, port, approve_hook):
        super().__init__(daemon=True)
        self.port, self.approve_hook = port, approve_hook
        self.httpd = None
    def run(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hook = self.approve_hook
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass
            def _go(self):
                ip = self.client_address[0]
                hook(ip)
                body = (b'<html><head><meta http-equiv="refresh" content="0;url=https://www.google.com">'
                        b'<title>Connected</title></head><body style="font-family:sans-serif;text-align:center;margin-top:4em">'
                        b'<h1>Connected!</h1><p>Taking you to <a href="https://www.google.com">google.com</a>...</p>'
                        b'<script>location.replace("https://www.google.com")</script></body></html>')
                self.send_response(302)
                self.send_header('Location', 'https://www.google.com')
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = do_HEAD = _go
        self.httpd = ThreadingHTTPServer((AP_IP if bindable(AP_IP) else '0.0.0.0', self.port), H)
        self.httpd.serve_forever()
    def stop(self):
        if self.httpd:
            self.httpd.shutdown()

def bindable(ip):
    try:
        s = socket.socket(); s.bind((ip, 0)); s.close()
        return True
    except OSError:
        return False

# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, runner=None):
        self.r = runner or Runner()
        self.procs = []
        self.portal = None
        self.hijack = None
        self.running = False
        self.cfg = {}

    def approve(self, ip):
        if ipaddress.ip_address(ip) in GUEST_NET:
            self.r('ipset', 'add', IPSET, ip, '-exist')

    def start(self, uplink, base, ap, ssid, psk, channel=6, hw_mode='g'):
        os.makedirs(STATE_DIR, exist_ok=True)
        open(LEASES, 'a').close()
        self.r('iptables-save', '-f', SNAPSHOT)
        self.cfg = {'ap': ap, 'base': base, 'uplink': uplink, 'ssid': ssid}
        self._created_ap = False
        try:
            self._start_inner(uplink, base, ap, ssid, psk, channel, hw_mode)
        except Exception:
            self._cleanup(ap, self._created_ap)
            raise

    def _start_inner(self, uplink, base, ap, ssid, psk, channel, hw_mode):
        if ap not in interfaces():
            self.r('iw', 'dev', base, 'interface', 'add', ap, 'type', '__ap')
            self._created_ap = True
        with open(os.path.join(STATE_DIR, 'hostapd.conf'), 'w') as f:
            f.write(hostapd_conf(ap, ssid, psk, channel, hw_mode))
        with open(os.path.join(STATE_DIR, 'dnsmasq.conf'), 'w') as f:
            f.write(dnsmasq_conf(ap))
        self.r('ip', 'addr', 'flush', 'dev', ap, ok_rc=(0, 1))
        self.r('ip', 'link', 'set', ap, 'up')
        self.r('ip', 'addr', 'add', '%s/24' % AP_IP, 'dev', ap)
        for line in iptables_script(ap, uplink).splitlines()[1:]:
            self.r('bash', '-c', line)
        self.procs = [
            subprocess.Popen(['hostapd', os.path.join(STATE_DIR, 'hostapd.conf')],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            subprocess.Popen(['dnsmasq', '-C', os.path.join(STATE_DIR, 'dnsmasq.conf')],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        time.sleep(1)
        for p in self.procs:
            if p.poll() is not None:
                raise RuntimeError('hostapd/dnsmasq exited at start - this adapter may not support hotspot+wifi at once (a USB wifi adapter works)')
        self.hijack = HijackDNS(AP_IP if bindable(AP_IP) else '0.0.0.0', HIJACK_DNS_PORT, AP_IP)
        self.hijack.start()
        self.portal = Portal(PORTAL_PORT, self.approve)
        self.portal.start()
        with open(PIDFILE, 'w') as f:
            json.dump({'pids': [p.pid for p in self.procs], 'ap': ap, 'base': base,
                       'uplink': uplink, 'ssid': ssid}, f)
        self.running = True

    def _cleanup(self, ap, created_ap):
        for p in self.procs:
            try: p.terminate()
            except Exception: pass
        self.procs = []
        if self.portal: self.portal.stop()
        if self.hijack: self.hijack.stop()
        for line in teardown_script(ap).splitlines():
            self.r('bash', '-c', line, ok_rc=(0, 1, 2))
        if created_ap:
            self.r('iw', 'dev', ap, 'del', ok_rc=(0, 1, 2))
        if os.path.exists(SNAPSHOT):
            self.r('iptables-restore', SNAPSHOT, ok_rc=(0, 1, 2))

    def stop(self):
        ap = self.cfg.get('ap')
        created = getattr(self, '_created_ap', False)
        if not ap and os.path.exists(PIDFILE):
            d = json.load(open(PIDFILE))
            ap, created = d.get('ap'), True
        if ap:
            self._cleanup(ap, created)
        try: os.remove(PIDFILE)
        except Exception: pass
        self.running = False

    def clients(self):
        outl = []
        try:
            for line in open(LEASES):
                parts = line.split()
                if len(parts) >= 4:
                    outl.append({'mac': parts[1], 'ip': parts[2], 'host': parts[3],
                                 'approved': ip_in_ipset(parts[2])})
        except Exception:
            pass
        return outl

def ip_in_ipset(ip):
    return ip in out('ipset', 'list', IPSET)

def ensure_deps(log=print):
    missing = [d for d in DEPS if not shutil.which(d)]
    if not missing:
        return []
    log('installing: %s ...' % ', '.join(missing))
    subprocess.run(['apt-get', 'update', '-qq'], capture_output=True)
    pkgs = {'iwgetid': 'wireless-tools'}
    subprocess.run(['apt-get', 'install', '-y', '-qq'] + [pkgs.get(m, m) for m in missing])
    return [d for d in DEPS if not shutil.which(d)]

# ---------------------------------------------------------------- curses UI
def draw(scr, st):
    scr.erase()
    h, w = scr.getmaxyx()
    def put(y, x, s, a=0):
        if 0 <= y < h and x < w:
            scr.addnstr(y, x, s, w - x - 1, a)
    put(0, 2, 'GUESTWING v%s' % VERSION, curses.A_BOLD)
    put(0, w - 16, 'guest wifi tool', curses.A_DIM)
    put(1, 2, 'internet-only hotspot - instant-approve captive portal', curses.A_DIM)
    put(3, 2, 'State:   %s' % st['state'], curses.A_BOLD if st['state'] == 'RUNNING' else 0)
    put(4, 2, 'SSID:    %s   (%s)' % (st['ssid'], st['sec']))
    put(5, 2, 'Uplink:  %s' % st['uplink'])
    put(6, 2, 'Hotspot: %s   gateway %s' % (st['ap'], AP_IP))
    if st.get('warn'):
        put(7, 2, '! %s' % st['warn'], curses.A_BOLD)
    y = 9
    put(y, 2, 'Clients (%d):' % len(st['clients']), curses.A_BOLD); y += 1
    for c in st['clients'][:h - y - 4]:
        put(y, 4, '%-16s %-18s %-20s %s' % (c['ip'], c['mac'], c['host'], 'approved' if c['approved'] else 'pending'))
        y += 1
    if not st['clients']:
        put(y, 4, '(none yet)', curses.A_DIM); y += 1
    put(h - 2, 2, '[s] start/stop (2x)   [n] name   [p] password   [q] quit', curses.A_REVERSE)
    scr.refresh()

def ui(scr):
    curses.curs_set(0)
    scr.timeout(1000)
    eng = Engine()
    uplink, base, ap, warn = plan_interfaces()
    cli_ssid = sys.argv[sys.argv.index('--ssid') + 1] if '--ssid' in sys.argv else None
    cli_psk = sys.argv[sys.argv.index('--psk') + 1] if '--psk' in sys.argv else None
    ssid = cli_ssid or os.environ.get('GW_SSID') or DEFAULT_SSID
    psk = cli_psk if cli_psk is not None else (os.environ['GW_PSK'] if 'GW_PSK' in os.environ else DEFAULT_PSK)
    psk_src = 'custom' if cli_psk is not None else 'default pw'
    ch, mode = sta_channel(base) if base else (None, None)
    arm = None
    while True:
        st = {'state': 'RUNNING' if eng.running else 'STOPPED',
              'ssid': ssid, 'sec': ('WPA2 ' + psk_src) if psk else 'open',
              'uplink': uplink or '-', 'ap': (ap or '-') + (' ch %s' % ch if ch else ''),
              'warn': warn, 'clients': eng.clients() if eng.running else []}
        draw(scr, st)
        h, w = scr.getmaxyx()
        if arm == 'start':
            scr.addnstr(h - 3, 2, 'adds the %s hotspot on ch %s; your own wifi stays up - s again to confirm' % (ssid, ch or '?'), w - 4, curses.A_BOLD)
        elif arm == 'quit':
            scr.addnstr(h - 3, 2, 'hotspot RUNNING - q again to stop everything and quit', w - 4, curses.A_BOLD)
        scr.refresh()
        k = scr.getch()
        if k in (ord('q'), 27):
            if eng.running:
                if arm == 'quit':
                    eng.stop(); break
                arm = 'quit'
            else:
                break
        elif k == ord('n') and not eng.running:
            curses.echo()
            scr.timeout(-1)
            scr.addnstr(h - 3, 2, 'hotspot name: ' + ' ' * 40, w - 4, 0)
            scr.addnstr(h - 3, 2, 'hotspot name: ', w - 4, curses.A_BOLD)
            scr.refresh()
            try:
                v = scr.getstr(h - 3, 16, 32).decode().strip()
            except Exception:
                v = ''
            curses.noecho()
            scr.timeout(1000)
            if v:
                ssid = v
            arm = None
        elif k == ord('p') and not eng.running:
            curses.echo()
            scr.timeout(-1)
            scr.addnstr(h - 3, 2, 'guest password (8+ chars, empty = open): ' + ' ' * 20, w - 4, 0)
            scr.addnstr(h - 3, 2, 'guest password (8+ chars, empty = open): ', w - 4, curses.A_BOLD)
            scr.refresh()
            try:
                v = scr.getstr(h - 3, 43, 32).decode().strip()
            except Exception:
                v = ''
            curses.noecho()
            scr.timeout(1000)
            if v and len(v) >= 8:
                psk, psk_src = v, 'custom'
            elif v == '':
                psk, psk_src = None, ''
            arm = None
        elif k == ord('s'):
            if eng.running:
                eng.stop(); arm = None
            elif arm == 'start':
                arm = None
                try:
                    eng.start(uplink, base, ap, ssid, psk, ch or 6, mode or 'g')
                except Exception as e:
                    scr.addnstr(h - 3, 2, 'start failed: %s' % e, w - 4, curses.A_BOLD)
                    scr.refresh(); scr.timeout(4000); scr.getch(); scr.timeout(1000)
            elif ap and uplink:
                arm = 'start'
            else:
                arm = None
        elif k != -1:
            arm = None
    return eng.running

def main():
    if '--dry-run' in sys.argv:
        uplink, base, ap, warn = plan_interfaces()
        cli_ssid = sys.argv[sys.argv.index('--ssid') + 1] if '--ssid' in sys.argv else None
        cli_psk = sys.argv[sys.argv.index('--psk') + 1] if '--psk' in sys.argv else None
        ssid = cli_ssid or os.environ.get('GW_SSID') or DEFAULT_SSID
        psk = cli_psk if cli_psk is not None else (os.environ['GW_PSK'] if 'GW_PSK' in os.environ else DEFAULT_PSK)
        ch, mode = sta_channel(base) if base else (None, None)
        print('uplink=%s base=%s ap=%s channel=%s mode=%s warn=%s ssid=%s psk=%s'
              % (uplink, base, ap, ch, mode, warn, ssid, 'yes' if psk else 'no'))
        print('--- hostapd.conf ---\n' + hostapd_conf(ap or 'wlan0_ap', ssid, psk, ch or 6, mode or 'g'))
        print('--- dnsmasq.conf ---\n' + dnsmasq_conf(ap or 'wlan0_ap'))
        print('--- iptables ---\n' + iptables_script(ap or 'wlan0_ap', uplink or 'wlan0'))
        return 0
    if os.geteuid() != 0:
        os.execvp('sudo', ['sudo', sys.executable, os.path.abspath(__file__)] + sys.argv[1:])
    left = curses.wrapper(ui)
    if left:
        print('guestwing: hotspot left stopped.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
