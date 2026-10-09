#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# wl-client.py — wl-vpn Client (runs on RUS2/Russia)
#
# Architecture:
#   TUN wltun0  →  PriorityQueue  →  8x PersistentSMTP  →  MP80:2525
#   UDP:10080   →  RTP recv  →  decrypt  →  decompress  →  TUN wltun0
#   At startup  →  send authenticated registration via SMTP
#   Periodic    →  re-registration + RTP path probe
#
# Config via environment variables (see config_loader.py)

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
import hmac
import subprocess
import collections
import zstandard as zstd
import signal
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config_loader import get_client_config, save_roc_state

# ── Load config ────────────────────────────────────────────────────────────────
CFG = get_client_config()

TUNSETIFF     = 0x400454ca
IFF_TUN       = 0x0001
IFF_NO_PI     = 0x1000

# ── Logging config (from env) ────────────────────────────────────────────────
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOG_RATE_LIMIT = int(os.environ.get('LOG_RATE_LIMIT', '0'))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s'
)

if LOG_RATE_LIMIT > 0:
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

    def _ratelimited_info(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.INFO, msg, *args, **kwargs)
    def _ratelimited_debug(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.DEBUG, msg, *args, **kwargs)
    logging.info = _ratelimited_info
    logging.debug = _ratelimited_debug

# ── Constants from config ──────────────────────────────────────────────────────
TUN_DEV            = CFG['tun_dev']
TUN_IP             = CFG['tun_ip']
TUN_GW             = CFG['tun_gw']
SMTP_PORT          = CFG['smtp_port']
RTP_PORT           = CFG['rtp_port']
REG_MAGIC          = CFG['reg_magic']
FRAG_MAGIC         = CFG['frag_magic']
ACK_THRESHOLD      = CFG['ack_threshold']
MAX_BATCH_PKTS     = CFG['max_batch_pkts']
MAX_BATCH_BYTES    = CFG['max_batch_bytes']
TX_STREAMS         = CFG['tx_streams']
BATCH_MS_MAX       = CFG['batch_ms_max']
BATCH_MS_MIN       = CFG['batch_ms_min']
RTP_TIMEOUT        = CFG['rtp_timeout']

# Crypto keys (separate per direction)
RTP_KEY_RX         = CFG['rtp_key_rx']   # for decrypting server→client
RTP_KEY_TX         = CFG['rtp_key_tx']   # for encrypting client→server (future use)
REG_AUTH_KEY       = CFG['reg_auth_key'] # for signing registration

# ROC persistence
ROC_STATE          = CFG['roc_state']
ROC                = ROC_STATE.get('roc', 0)
SEQ                = ROC_STATE.get('seq', 0)

# RTP recovery
RTP_RECOVERY_ENABLED = CFG['rtp_recovery_enabled']
RTP_RECOVERY_INTERVAL = CFG['rtp_recovery_interval']
RTP_PROBE_INTERVAL  = CFG['rtp_probe_interval']

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
        with self.cond:
            self.acks.appendleft(data)
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
rtp_alive = threading.Event()
rtp_last_rx = 0  # timestamp of last RTP packet received

# ── TUN ────────────────────────────────────────────────────────────────────────
def get_own_ipv6():
    try:
        out = subprocess.check_output(['ip', '-6', 'addr', 'show', 'scope', 'global'],
                                      text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'temporary' not in line and TUN_DEV not in line:
                addr = line.split()[1].split('/')[0]
                if addr and not addr.startswith('fd'):
                    return addr
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

    subprocess.run(['ip', 'route', 'replace', 'default', 'via', TUN_GW, 'dev', TUN_DEV,
                    'metric', '50'], check=False, capture_output=True)

    for cmd in [
        ['iptables', '-t', 'mangle', '-C', 'FORWARD', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
        ['iptables', '-t', 'mangle', '-C', 'OUTPUT',  '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--clamp-mss-to-pmtu'],
    ]:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            subprocess.run(cmd[:5] + ['-A'] + cmd[6:], check=False)

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


def tun_reader(tun_fd):
    threading.current_thread().name = 'TUN-READ'
    while True:
        try:
            pkt = os.read(tun_fd, 65535)
            if pkt:
                tx_queue.put(pkt)
        except OSError:
            time.sleep(0.001)


# ── PersistentSMTP ─────────────────────────────────────────────────────────────
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
        self._read_line()
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


# ── Registration with HMAC authentication ──────────────────────────────────────
def build_registration(server_host: str) -> bytes:
    """Build authenticated registration payload."""
    global ROC, SEQ
    own_ipv6 = get_own_ipv6()
    if not own_ipv6:
        logging.warning('REG: could not determine own IPv6, using IPv4')
        own_ipv6 = socket.gethostbyname(socket.gethostname())

    reg_data = json.dumps({
        'ipv6': own_ipv6,
        'rtp_port': RTP_PORT,
        'roc': ROC,
        'seq': SEQ,
        'ts': int(time.time())
    }).encode()

    # HMAC-SHA256 over registration data
    auth_tag = hmac.new(REG_AUTH_KEY, reg_data, hashlib.sha256).digest()
    payload = REG_MAGIC + auth_tag + reg_data
    return struct.pack('!I', len(payload)) + payload


def send_registration(server_host: str) -> bool:
    """Send authenticated registration to server."""
    framed = build_registration(server_host)
    logging.info(f'REG: sending authenticated registration')
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


# ── RTP RX with ROC persistence ────────────────────────────────────────────────
class ReplayWindow:
    def __init__(self, size=65536):  # increased to cover full seq space
        self.size   = size
        self.bitmap = 0
        self.max_seq = -1

    def check(self, seq):
        global ROC
        full_seq = (ROC << 32) | seq
        if self.max_seq < 0:
            self.max_seq = full_seq
            self.bitmap  = 1
            return True
        if full_seq > self.max_seq:
            shift = min(full_seq - self.max_seq, self.size)
            self.bitmap = (self.bitmap << shift) & ((1 << self.size) - 1)
            self.bitmap |= 1
            self.max_seq = full_seq
            ROC = full_seq >> 32
            return True
        delta = self.max_seq - full_seq
        if delta >= self.size: return False
        bit = 1 << delta
        if self.bitmap & bit: return False
        self.bitmap |= bit
        return True


def build_nonce(seq: int) -> bytes:
    """Build 12-byte nonce: ROC (4B) + SEQ (4B) + zeros (4B)."""
    full_seq = (ROC << 32) | (seq & 0xFFFFFFFF)
    return struct.pack('!Q', full_seq) + b'\x00\x00\x00\x00'


def rtp_rx_thread(tun_fd):
    global ROC, SEQ, rtp_last_rx
    threading.current_thread().name = 'RTP-RX'
    cipher  = ChaCha20Poly1305(RTP_KEY_RX)
    dctx    = zstd.ZstdDecompressor()
    replay  = ReplayWindow()
    frags   = {}

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.settimeout(5.0)
    sock.bind(('::', RTP_PORT))

    stat_bytes = 0
    stat_time  = time.monotonic()

    logging.info(f'RTP-RX: listening on UDP [::]:{RTP_PORT}')

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

        b0, b1, seq, ts, ssrc = struct.unpack_from('!BBHII', data)
        if (b0 >> 6) != 2: continue
        pt = b1 & 0x7F
        if pt != 96: continue

        rtp_header = data[:12]
        encrypted  = data[12:]

        if not replay.check(seq): continue

        nonce = build_nonce(seq)
        try:
            payload = cipher.decrypt(nonce, encrypted, rtp_header)
        except Exception:
            continue

        rtp_alive.set()
        rtp_last_rx = time.monotonic()
        stat_bytes += len(data)

        if len(payload) < 8: continue
        magic, rtp_seq, frag_idx, frag_total, _ = struct.unpack_from('!HHBBH', payload)
        if magic != FRAG_MAGIC: continue
        chunk = payload[8:]

        if frag_total == 1:
            process_payload(chunk)
        else:
            key = rtp_seq
            if key not in frags:
                frags[key] = {'total': frag_total, 'parts': {}, 'ts': time.monotonic()}
            frags[key]['parts'][frag_idx] = chunk
            if len(frags[key]['parts']) == frags[key]['total']:
                assembled = b''.join(frags[key]['parts'][i]
                                     for i in range(frags[key]['total']))
                del frags[key]
                process_payload(assembled)
            now = time.monotonic()
            stale = [k for k, v in frags.items() if now - v['ts'] > 5.0]
            for k in stale: del frags[k]

        now = time.monotonic()
        if now - stat_time >= 10:
            mbps = (stat_bytes * 8) / ((now - stat_time) * 1_000_000)
            logging.info(f'RTP-RX: {mbps:.2f} Mbps from [{addr[0]}]')
            stat_bytes = 0; stat_time = now


# ── RTP Recovery: periodic re-registration + probe ─────────────────────────────
def rtp_recovery_thread(server_host: str, tun_fd: int):
    """Periodically check RTP health and re-register if needed."""
    global ROC, SEQ, rtp_last_rx
    threading.current_thread().name = 'RTP-RECOVERY'

    if not RTP_RECOVERY_ENABLED:
        logging.info('RTP recovery disabled')
        return

    last_reg = 0
    last_probe = 0

    while True:
        now = time.monotonic()
        try:
            # Check if RTP path is alive
            rtp_ok = (now - rtp_last_rx) < RTP_RECOVERY_INTERVAL

            if not rtp_ok and (now - last_reg) >= RTP_RECOVERY_INTERVAL:
                logging.warning('RTP path appears down, re-registering...')
                if send_registration(server_host):
                    last_reg = now
                    rtp_alive.clear()
                    # Wait for RTP to come back
                    if rtp_alive.wait(timeout=RTP_TIMEOUT):
                        logging.info('RTP channel restored')
                    else:
                        logging.warning('RTP still down after re-registration')

            # Periodic probe registration (even if RTP seems ok)
            if (now - last_probe) >= RTP_PROBE_INTERVAL:
                # Just send a lightweight registration to keep server state fresh
                send_registration(server_host)
                last_probe = now

        except Exception as e:
            logging.error(f'RTP recovery error: {e}')

        time.sleep(5)


# ── Graceful shutdown ──────────────────────────────────────────────────────────
_shutdown = threading.Event()

def signal_handler(signum, frame):
    logging.info(f'Received signal {signum}, shutting down...')
    _shutdown.set()

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    global ROC, SEQ
    if len(sys.argv) < 2:
        print('Usage: wl-client.py <server_ip>')
        sys.exit(1)

    server_ip = sys.argv[1]
    logging.info(f'wl-client starting, server={server_ip}, ROC={ROC}, SEQ={SEQ}')

    tun_fd = create_tun()

    # Start threads
    threading.Thread(target=tun_reader, args=(tun_fd,), daemon=True, name='TUN-READ').start()
    threading.Thread(target=rtp_rx_thread, args=(tun_fd,), daemon=True, name='RTP-RX').start()
    threading.Thread(target=rtp_recovery_thread, args=(server_ip, tun_fd), daemon=True, name='RTP-RECOVERY').start()

    for i in range(TX_STREAMS):
        threading.Thread(target=smtp_tx_thread, args=(i, server_ip),
                         daemon=True, name=f'SMTP-{i}').start()

    # Initial registration
    time.sleep(3)
    send_registration(server_ip)

    if rtp_alive.wait(timeout=RTP_TIMEOUT):
        logging.info('RTP channel alive — asymmetric mode active')
    else:
        logging.warning('No RTP received — running in SMTP-only mode (degraded)')

    # Main loop with periodic ROC save
    last_roc_save = time.monotonic()
    while not _shutdown.is_set():
        _shutdown.wait(timeout=30)
        now = time.monotonic()
        if now - last_roc_save >= 60:
            save_roc_state('client', ROC, SEQ)
            last_roc_save = now
            logging.info(f'wl-client alive, rtp={rtp_alive.is_set()}, ROC={ROC}, SEQ={SEQ}')

    # Final save on shutdown
    save_roc_state('client', ROC, SEQ)
    logging.info('wl-client stopped')


if __name__ == '__main__':
    main()