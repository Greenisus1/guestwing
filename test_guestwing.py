import json, os, socket, struct, sys, tempfile, threading, time, unittest, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guestwing as g

WPA = '''
network={
    ssid="HomeNet"
    psk="secret123"
    key_mgmt=WPA-PSK
}
network={
    ssid="CafeOpen"
    key_mgmt=NONE
}
'''

def make_query(name=b'example.com', qtype=1):
    tid = 0x1234
    q = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    for part in name.split(b'.'):
        q += bytes([len(part)]) + part
    q += b'\x00' + struct.pack('>HH', qtype, 1)
    return q

class ConfTests(unittest.TestCase):
    def test_wpa_parse(self):
        creds = g.parse_wpa_conf(WPA)
        self.assertEqual(creds['HomeNet'], 'secret123')
        self.assertIsNone(creds['CafeOpen'])
    def test_hostapd_wpa(self):
        c = g.hostapd_conf('wlan0_ap', 'HomeNet', 'secret123', channel=11, hw_mode='g')
        self.assertIn('ssid=HomeNet', c)
        self.assertIn('channel=11', c)
        self.assertIn('wpa=2', c)
        self.assertIn('wpa_passphrase=secret123', c)
        self.assertIn('interface=wlan0_ap', c)
    def test_hostapd_open(self):
        c = g.hostapd_conf('wlan0_ap', 'HomeNet', None, channel=6, hw_mode='g')
        self.assertNotIn('wpa=2', c)
    def test_dnsmasq(self):
        c = g.dnsmasq_conf('wlan0_ap')
        self.assertIn('interface=wlan0_ap', c)
        self.assertIn('dhcp-range=192.168.50.100,192.168.50.200', c)
        self.assertIn('dhcp-option=6,192.168.50.1', c)
    def test_iptables_rules(self):
        s = g.iptables_script('wlan0_ap', 'wlan0')
        self.assertIn('REDIRECT --to-ports 8080', s)
        self.assertIn('REDIRECT --to-ports 5353', s)
        for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'):
            self.assertIn('-d %s -j DROP' % net, s)  # LAN isolation
        self.assertIn('-o wlan0 -j ACCEPT', s)
        self.assertIn('MASQUERADE', s)
        self.assertIn('ip_forward=1', s)
    def test_teardown(self):
        s = g.teardown_script('wlan0_ap')
        self.assertIn('GW_CAP', s)
        self.assertIn('ipset destroy', s)

class DnsTests(unittest.TestCase):
    def test_answer_bytes(self):
        resp = g.dns_answer(make_query(), '192.168.50.1')
        self.assertEqual(resp[:2], b'\x124')
        an = struct.unpack('>H', resp[6:8])[0]
        self.assertEqual(an, 1)
        self.assertEqual(resp[-4:], socket.inet_aton('192.168.50.1'))
    def test_live_hijack(self):
        srv = g.HijackDNS('127.0.0.1', 15353, '192.168.50.1')
        srv.start()
        time.sleep(0.2)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(make_query(b'anything.example'), ('127.0.0.1', 15353))
        data, _ = s.recvfrom(512)
        self.assertEqual(data[-4:], socket.inet_aton('192.168.50.1'))
        s.close(); srv.stop()

class PortalTests(unittest.TestCase):
    def test_auto_approve_redirect(self):
        got = []
        p = g.Portal(18080, got.append)
        p.start()
        time.sleep(0.4)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        for path in ('/hotspot-detect.html', '/generate_204', '/connecttest.txt', '/anything'):
            try:
                opener.open('http://127.0.0.1:18080' + path, timeout=3)
                self.fail('expected redirect')
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 302)
                self.assertEqual(e.headers['Location'], 'https://www.google.com')
        self.assertEqual(got, ['127.0.0.1'] * 4)
        p.stop()

class PlanTests(unittest.TestCase):
    def test_single_radio_clone(self):
        g.interfaces = lambda: ['eth0', 'wlan0']
        g.is_wireless = lambda i: i == 'wlan0'
        g.default_route_ifaces = lambda: ['wlan0']
        g.sta_channel = lambda i: (6, 'g')
        uplink, base, ap, warn = g.plan_interfaces()
        self.assertEqual((uplink, base, ap, warn), ('wlan0', 'wlan0', 'wlan0_ap', None))
    def test_no_uplink(self):
        g.interfaces = lambda: ['wlan0']
        g.is_wireless = lambda i: True
        g.default_route_ifaces = lambda: []
        _, _, _, warn = g.plan_interfaces()
        self.assertIn('no internet connection', warn)
    def test_eth_uplink(self):
        g.interfaces = lambda: ['eth0', 'wlan0']
        g.is_wireless = lambda i: i == 'wlan0'
        g.default_route_ifaces = lambda: ['eth0']
        uplink, base, ap, warn = g.plan_interfaces()
        self.assertEqual((uplink, base, ap), ('eth0', 'wlan0', 'wlan0_ap'))

class EngineTests(unittest.TestCase):
    def test_approve_scope(self):
        planned = []
        class R:
            def __call__(self, *a, **k): planned.append(a)
        e = g.Engine()
        e.r = R()
        e.approve('192.168.50.123')
        e.approve('8.8.8.8')  # outside guest net: ignored
        self.assertEqual(len(planned), 1)
        self.assertIn('192.168.50.123', planned[0])

if __name__ == '__main__':
    unittest.main()
