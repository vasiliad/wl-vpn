#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# wl-client.py — wl-vpn Client (runs on RUS2/Russia)
#
# Architecture:
#   TUN wltun0  →  PriorityQueue  →  8x PersistentSMTP  →  MP80:2525
#   UDP:10080   →  RTP recv  →  decrypt  →  decompress  →  TUN wltun0
#   At startup  →  send registration via SMTP
#
# Config via environment variables (see config_loader.py):
#   PSK_HEX, RTP_PORT, SMTP_PORT, TUN_DEV, TUN_IP, TUN_GW, etc.

import os
import sys
import fcntl
import struct
import time
import socket
import logging
import threading
import base64
import json
import hashlib
import subprocess
import collections
import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config_loader import get_client_config

# ── Load config ────────────────────────────────────────────────────────────────
CFG = get_client_config()

TUNSETIFF     = 0x400454ca
IFF_TUN       = 0x0001
IFF_NO_PI     = 0x1000

# ── Logging config (from env) ────────────────────────────────────────────────
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOG_RATE_LIMIT = int(os.environ.get('LOG_RATE_LIMIT', '0'))  # 0 = no limit

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s'
)

# Optional: simple rate limiter for INFO/DEBUG to prevent log spam
if LOG_RATE_LIMIT > 0:
    import functools
    _last_log = {}
    _log_lock = threading.Lock()

    def rate_limited_log(logger, level, msg, *args, **kwargs):
        now = time.monotonic()
        key = (level, msg[:50])
        with _log_lock:
            last = _last_log.get(key, 0)
            if now - last >= LOG_RATE_LIMIT:
                _last_log[key] = now
                logger.log(level, msg, *args, **kwargs)
            elif level >= logging.WARNING:
                logger.log(level, msg, *args, **kwargs)

    # Patch logging methods
    _orig_info = logging.info
    _orig_debug = logging.debug
    def _ratelimited_info(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.INFO, msg, *args, **kwargs)
    def _ratelimited_debug(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.DEBUG, msg, *args, **kwargs)
    logging.info = _ratelimited_info
    logging.debug = _ratelimited_debug

# ── Constants from config ──────────────────────────────────────────────────────
TUN_DEV       = CFG['tun_dev']
TUN_IP        = CFG['tun_ip']
TUN_GW        = CFG['tun_gw']
SMTP_PORT     = CFG['smtp_port']
RTP_PORT      = CFG['rtp_port']
REG_MAGIC     = CFG['reg_magic']
FRAG_MAGIC    = CFG['frag_magic']
ACK_THRESHOLD = CFG['ack_threshold']
MAX_BATCH_PKTS = CFG['max_batch_pkts']
MAX_BATCH_BYTES = CFG['max_batch_bytes']
TX_STREAMS    = CFG['tx_streams']
BATCH_MS_MAX  = CFG['batch_ms_max']
BATCH_MS_MIN  = CFG['batch_ms_min']
RTP_TIMEOUT   = CFG['rtp_timeout']
RTP_KEY       = CFG['rtp_key']

# ── Priority Queue ─────────────────────────────────────────────────────────────
class PriorityQueue:
    def __init__(self):
        self.acks  = collections.deque()
        self.norms = collections.deque()
        self.cond  = threading.Condition()

    def put(self, pkt):
        with self.cond:
            if len(pkt) <= ACK_THRESHOLD:
                if len(self.acks) < 2000: self.acks.append(pkt)
            else:
                if len(self.norms) < 20000: self.norms.append(pkt)
            self.cond.notify()

    def put_raw(self, data):
        """Put pre-framed raw data as single item (used for registration)."""
        with self.cond:
            self.acks.appendleft(data)   # highest priority
            self.cond.notify()

    def get_batch(self):
        pkts = []
        total = 0
        with self.cond:
            self.cond.wait_for(lambda: self.acks or self.norms, timeout=BATCH_MS_MAX)
            while self.acks and len(pkts) < MAX_BATCH_PKTS and total < MAX_BATCH_BYTES:
                p = self.acks.popleft(); pkts.append(p); total += len(p)
            while self.norms and len(pkts) < MAX_BATCH_PKTS and total < MAX_BATCH_BYTES:
                p = self.norms.popleft(); pkts.append(p); total += len(p)
        if pkts:
            deadline = time.monotonic() + BATCH_MS_MIN
            with self.cond:
                while True:
                    remain = deadline - time.monotonic()
                    if remain <= 0 or len(pkts) >= MAX_BATCH_PKTS: break
                    if not self.cond.wait(timeout=remain): break
                    while self.acks and len(pkts) < MAX_BATCH_PKTS:
                        p = self.acks.popleft(); pkts.append(p)
                    while self.norms and len(pkts) < MAX_BATCH_PKTS:
                        p = self.norms.popleft(); pkts.append(p)
        return pkts


tx_queue = PriorityQueue()
rtp_alive = threading.Event()   # set when first RTP packet received

# ── TUN ────────────────────────────────────────────────────────────────────────
def get_own_ipv6():
    """Parse own global IPv6 from ip addr."""
    try:
        out = subprocess.check_output(['ip', '-6', 'addr', 'show', 'scope', 'global'],
                                      text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'temporary' not in line and TUN_DEV not in line:
                addr = line.split()[1].split('/')[0]
                if addr and not addr.startswith('fd'):   # prefer public, not Tailscale
                    return addr
        # fallback: any global
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('inet6'):
                addr = line.split()[1].split('/')[0]
                return addr
    except Exception:
        pass
    return None


def create_tun():
    subprocess.run(['ip', 'link', 'delete', TUN_DEV], check=False, capture_output=True)
    time.sleep(0.3)
    fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', TUN_DEV.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    subprocess.run(['ip', 'addr', 'flush', 'dev', TUN_DEV], check=False, capture_output=True)
    subprocess.run(['ip', 'addr', 'add', TUN_IP, 'dev', TUN_DEV], check=False)
    subprocess.run(['ip', 'link', 'set', TUN_DEV, 'mtu', '1400'], check=False)
    subprocess.run(['ip', 'link', 'set', TUN_DEV, 'txqueuelen', '10000'], check=False)
    subprocess.run(['ip', 'link', 'set', TUN_DEV, 'up'], check=False)
    subprocess.run(['sysctl', '-w', 'net.core.rmem_max=16777216'], check=False, capture_output=True)
    subprocess.run(['sysctl', '-w', 'net.core.wmem_max=16777216'], check=False, capture_output=True)

    # Default route via tunnel (all traffic)
    subprocess.run(['ip', 'route', 'replace', 'default', 'via', TUN_GW, 'dev', TUN_DEV,
                    'metric', '50'], check=False, capture_output=True)

    # MSS clamping — prevent TCP fragmentation issues
    for cmd in [
        ['iptables',  '-t', 'mangle', '-C', 'FORWARD', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
        ['iptables',  '-t', 'mangle', '-C', 'OUTPUT',  '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
    ]:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            subprocess.run(cmd[:5] + ['-A'] + cmd[6:], check=False)

    # CRITICAL: Do NOT route DNS through tunnel → avoids bootstrap deadlock
    # Keep 8.8.8.8 and server IP on direct path
    server_ip = sys.argv[1] if len(sys.argv) > 1 else ''
    for host in ['8.8.8.8', '8.8.4.4', '1.1.1.1', server_ip]:
        try:
            out = subprocess.check_output(['ip', 'route', 'get', host],
                                          text=True, stderr=subprocess.DEVNULL)
            if 'via' in out:
                gw = out.split('via')[1].split()[0]
                subprocess.run(['ip', 'route', 'replace', host + '/32', 'via', gw],
                               check=False, capture_output=True)
        except Exception as ex:
            logging.warning(f'route protect {host}: {ex}')

    logging.info(f'TUN {TUN_DEV} up as {TUN_IP}, default route → {TUN_GW}')
    return fd


# ── TUN reader → tx_queue ──────────────────────────────────────────────────────
def tun_reader(tun_fd):
    threading.current_thread().name = 'TUN-READ'
    while True:
        try:
            pkt = os.read(tun_fd, 65535)
            if pkt:
                tx_queue.put(pkt)
        except OSError:
            time.sleep(0.001)


# ── PersistentSMTP (same pattern as mp80-ip4) ──────────────────────────────────
TXN_HDR = (
    b"MAIL FROM:<tun@wl.local>\r\n"
    b"RCPT TO:<tun@mp80.local>\r\n"
    b"DATA\r\nSubject: tun\r\n\r\n"
)
TXN_END = b"\r\n.\r\n"


class PersistentSMTP:
    def __init__(self, host, idx):
        self.host   = host
        self.idx    = idx
        self.sock   = None
        self.buf    = bytearray()
        self.cctx   = zstd.ZstdCompressor(level=1)
        self._last_tx = time.monotonic()

    def _read_line(self):
        while b'\r\n' not in self.buf:
            chunk = self.sock.recv(8192)
            if not chunk: raise ConnectionError('EOF')
            self.buf.extend(chunk)
        idx = self.buf.index(b'\r\n')
        line = bytes(self.buf[:idx])
        del self.buf[:idx + 2]
        return line

    def _drain(self, n):
        for _ in range(n):
            l = self._read_line()
            code = int(l[:3])
            if code >= 500: raise ConnectionError(f'SMTP 5xx: {l}')

    def connect(self):
        s = socket.create_connection((self.host, SMTP_PORT), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        s.settimeout(25.0)
        self.sock = s
        self.buf.clear()
        self._last_tx = time.monotonic()
        self._read_line()   # 220 greeting
        self.sock.sendall(b'EHLO wl.local\r\n')
        while True:
            l = self._read_line()
            if l.startswith(b'250 ') or not l.startswith(b'250'): break
        logging.info(f'[SMTP-{self.idx}] connected to {self.host}:{SMTP_PORT}')

    def keepalive(self):
        if time.monotonic() - self._last_tx > 8:
            self.sock.sendall(b'NOOP\r\n')
            self._read_line()
            self._last_tx = time.monotonic()

    def send(self, batch):
        raw  = b''.join(struct.pack('!I', len(p)) + p for p in batch)
        body = base64.b64encode(self.cctx.compress(raw))
        self.sock.sendall(TXN_HDR + body + TXN_END)
        self._drain(4)
        self._last_tx = time.monotonic()

    def send_raw(self, raw_framed: bytes):
        """Send pre-framed data (e.g. registration packet)."""
        body = base64.b64encode(self.cctx.compress(raw_framed))
        self.sock.sendall(TXN_HDR + body + TXN_END)
        self._drain(4)
        self._last_tx = time.monotonic()

    def close(self):
        try:
            self.sock and self.sock.sendall(b'QUIT\r\n')
        except Exception: pass
        try:
            self.sock and self.sock.close()
        except Exception: pass
        self.sock = None


# ── SMTP TX threads ────────────────────────────────────────────────────────────
def smtp_tx_thread(idx, server_host):
    threading.current_thread().name = f'SMTP-{idx}'
    conn = PersistentSMTP(server_host, idx)
    stat_bytes = 0
    stat_time  = time.monotonic()

    while True:
        try:
            if conn.sock is None:
                conn.connect()

            batch = tx_queue.get_batch()
            if not batch:
                conn.keepalive()
                continue

            conn.send(batch)

            nb = sum(len(p) for p in batch)
            stat_bytes += nb
            now = time.monotonic()
            if now - stat_time >= 10:
                mbps = (stat_bytes * 8) / ((now - stat_time) * 1_000_000)
                logging.info(f'[SMTP-{idx}] TX {mbps:.2f} Mbps')
                stat_bytes = 0; stat_time = now

        except Exception as e:
            logging.error(f'[SMTP-{idx}] error: {e} — reconnect in 2s')
            conn.close()
            time.sleep(2)


# ── Registration ───────────────────────────────────────────────────────────────
def send_registration(server_host):
    """Send registration to server via a dedicated SMTP connection."""
    own_ipv6 = get_own_ipv6()
    if not own_ipv6:
        logging.warning('REG: could not determine own IPv6, using IPv4')
        own_ipv6 = socket.gethostbyname(socket.gethostname())

    reg = json.dumps({'ipv6': own_ipv6, 'rtp_port': RTP_PORT}).encode()
    payload = REG_MAGIC + reg
    framed  = struct.pack('!I', len(payload)) + payload

    logging.info(f'REG: sending registration, own IPv6={own_ipv6}')
    conn = PersistentSMTP(server_host, 'REG')
    for attempt in range(5):
        try:
            conn.connect()
            conn.send_raw(framed)
            conn.close()
            logging.info('REG: registration sent OK')
            return True
        except Exception as e:
            logging.error(f'REG attempt {attempt+1} failed: {e}')
            conn.close()
            time.sleep(3)
    return False


# ── RTP RX ─────────────────────────────────────────────────────────────────────
class ReplayWindow:
    def __init__(self, size=2048):
        self.size   = size
        self.bitmap = 0
        self.max_seq = -1

    def check(self, seq):
        if self.max_seq < 0:
            self.max_seq = seq
            self.bitmap  = 1
            return True
        if seq > self.max_seq:
            shift = min(seq - self.max_seq, self.size)
            self.bitmap = (self.bitmap << shift) & ((1 << self.size) - 1)
            self.bitmap |= 1
            self.max_seq = seq
            return True
        delta = self.max_seq - seq
        if delta >= self.size: return False
        bit = 1 << delta
        if self.bitmap & bit: return False
        self.bitmap |= bit
        return True


def rtp_rx_thread(tun_fd):
    threading.current_thread().name = 'RTP-RX'
    cipher  = ChaCha20Poly1305(RTP_KEY)
    dctx    = zstd.ZstdDecompressor()
    replay  = ReplayWindow()
    frags   = {}   # seq → {total, parts}

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.settimeout(5.0)
    sock.bind(('::', RTP_PORT))

    roc = 0
    stat_bytes = 0
    stat_time  = time.monotonic()

    logging.info(f'RTP-RX: listening on UDP [::]:{RTP_PORT}')

    def build_nonce(s):
        idx = (roc << 32) | (s & 0xFFFFFFFF)
        return struct.pack('!Q', idx) + b'\x00\x00\x00\x00'

    def process_payload(compressed):
        try:
            raw = dctx.decompress(compressed)
        except Exception as e:
            logging.warning(f'RTP-RX decompress error: {e}')
            return
        offset = 0
        while offset + 4 <= len(raw):
            plen = struct.unpack_from('!I', raw, offset)[0]
            offset += 4
            if plen == 0 or plen > 65535 or offset + plen > len(raw): break
            try:
                os.write(tun_fd, raw[offset:offset + plen])
            except OSError as e:
                logging.warning(f'TUN write: {e}')
            offset += plen

    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f'RTP-RX recv: {e}')
            time.sleep(0.1)
            continue

        if len(data) < 12: continue

        # Parse RTP header
        b0, b1, seq, ts, ssrc = struct.unpack_from('!BBHII', data)
        if (b0 >> 6) != 2: continue    # wrong version
        pt = b1 & 0x7F
        if pt != 96: continue          # wrong payload type

        rtp_header = data[:12]
        encrypted  = data[12:]

        if not replay.check(seq): continue

        nonce = build_nonce(seq)
        try:
            payload = cipher.decrypt(nonce, encrypted, rtp_header)
        except Exception:
            continue   # auth failed

        rtp_alive.set()
        stat_bytes += len(data)

        # Parse frag header (8 bytes): magic(2) rtp_seq(2) frag_idx(1) total(1) reserved(2)
        if len(payload) < 8: continue
        magic, rtp_seq, frag_idx, frag_total, _ = struct.unpack_from('!HHBBH', payload)
        if magic != FRAG_MAGIC: continue
        chunk = payload[8:]

        if frag_total == 1:
            # Single fragment — process directly
            process_payload(chunk)
        else:
            # Reassemble
            key = rtp_seq
            if key not in frags:
                frags[key] = {'total': frag_total, 'parts': {}, 'ts': time.monotonic()}
            frags[key]['parts'][frag_idx] = chunk
            if len(frags[key]['parts']) == frags[key]['total']:
                assembled = b''.join(frags[key]['parts'][i]
                                     for i in range(frags[key]['total']))
                del frags[key]
                process_payload(assembled)
            # Cleanup stale frag sets (> 5 seconds)
            now = time.monotonic()
            stale = [k for k, v in frags.items() if now - v['ts'] > 5.0]
            for k in stale: del frags[k]

        now = time.monotonic()
        if now - stat_time >= 10:
            mbps = (stat_bytes * 8) / ((now - stat_time) * 1_000_000)
            logging.info(f'RTP-RX: {mbps:.2f} Mbps from [{addr[0]}]')
            stat_bytes = 0; stat_time = now


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print('Usage: wl-client.py <server_ip>')
        sys.exit(1)

    server_ip = sys.argv[1]
    logging.info(f'wl-client starting, server={server_ip}')

    tun_fd = create_tun()

    threading.Thread(target=tun_reader,  args=(tun_fd,),  daemon=True, name='TUN-READ').start()
    threading.Thread(target=rtp_rx_thread, args=(tun_fd,), daemon=True, name='RTP-RX').start()

    for i in range(TX_STREAMS):
        threading.Thread(target=smtp_tx_thread, args=(i, server_ip),
                         daemon=True, name=f'SMTP-{i}').start()

    # Wait for SMTP streams to connect, then register
    time.sleep(3)
    send_registration(server_ip)

    # Check if RTP arrives within timeout
    if rtp_alive.wait(timeout=RTP_TIMEOUT):
        logging.info('RTP channel alive — asymmetric mode active')
    else:
        logging.warning('No RTP received — running in SMTP-only mode (degraded)')

    # Keep main thread alive
    while True:
        time.sleep(30)
        logging.info(f'wl-client alive, rtp={rtp_alive.is_set()}')


if __name__ == '__main__':
    main()