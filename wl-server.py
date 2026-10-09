#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# wl-server.py — wl-vpn Exit Node (runs on MP80/Israel)
#
# Architecture:
#   Haraka :2525  ← SMTP from wl-client (Russia)
#   Haraka plugin → /tmp/wl_tun.sock → THIS PROCESS → TUN wltun0
#   TUN wltun0    → RTP/SRTP/UDP → client IPv6:10080  (return traffic)
#   TUN wltun0    → NAT → Internet
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
import asyncio
import base64
import json
import hashlib
import random
import subprocess
import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config_loader import get_server_config

# ── Load config ────────────────────────────────────────────────────────────────
CFG = get_server_config()

TUNSETIFF    = 0x400454ca
IFF_TUN      = 0x0001
IFF_NO_PI    = 0x1000

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

    _orig_info = logging.info
    _orig_debug = logging.debug
    def _ratelimited_info(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.INFO, msg, *args, **kwargs)
    def _ratelimited_debug(msg, *args, **kwargs):
        rate_limited_log(logging.getLogger(), logging.DEBUG, msg, *args, **kwargs)
    logging.info = _ratelimited_info
    logging.debug = _ratelimited_debug

# ── Constants from config ──────────────────────────────────────────────────────
TUN_DEV      = CFG['tun_dev']
TUN_IP       = CFG['tun_ip']
TUN_GW       = CFG['tun_gw']
SOCK_PATH    = CFG['sock_path']
RTP_PORT     = CFG['rtp_port']
REG_MAGIC    = CFG['reg_magic']
FRAG_MAGIC   = CFG['frag_magic']
ACK_THRESHOLD = CFG['ack_threshold']
MAX_BATCH_PKTS = CFG['max_batch_pkts']
MAX_BATCH_BYTES = CFG['max_batch_bytes']
BATCH_MS_MAX = CFG['batch_ms_max']
BATCH_MS_MIN = CFG['batch_ms_min']
RTP_MTU      = CFG['rtp_mtu']
RTP_KEY      = CFG['rtp_key']

# ── Shared state ───────────────────────────────────────────────────────────────
client_ipv6 = None
client_port  = RTP_PORT
rtp_ready    = threading.Event()

# ── Priority Queue ─────────────────────────────────────────────────────────────
import collections

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

# ── TUN ────────────────────────────────────────────────────────────────────────
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
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=False, capture_output=True)
    subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'], check=False, capture_output=True)
    # NAT
    for cmd in [
        ['iptables',  '-t', 'nat', '-C', 'POSTROUTING', '-s', '10.0.200.0/30', '-j', 'MASQUERADE'],
        ['ip6tables', '-t', 'nat', '-C', 'POSTROUTING', '-s', '10.0.200.0/30', '-j', 'MASQUERADE'],
    ]:
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            subprocess.run(cmd[:-2] + ['-A'] + cmd[-2:], check=False)
    for chain in [['iptables', '-C', 'FORWARD', '-i', TUN_DEV, '-j', 'ACCEPT'],
                  ['iptables', '-C', 'FORWARD', '-o', TUN_DEV, '-j', 'ACCEPT']]:
        r = subprocess.run(chain, capture_output=True)
        if r.returncode != 0:
            subprocess.run(chain[:2] + ['-A'] + chain[3:], check=False)
    logging.info(f'TUN {TUN_DEV} up as {TUN_IP}, NAT enabled')
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


# ── RTP sender ─────────────────────────────────────────────────────────────────
def rtp_tx_thread():
    threading.current_thread().name = 'RTP-TX'
    cipher = ChaCha20Poly1305(RTP_KEY)
    cctx   = zstd.ZstdCompressor(level=1)
    ssrc   = random.getrandbits(32)
    seq    = random.randint(0, 65535)
    ts     = random.randint(0, 2**32 - 1)
    roc    = 0
    sock   = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    stat_bytes = 0
    stat_time  = time.monotonic()

    def build_nonce(s):
        idx = (roc << 32) | (s & 0xFFFFFFFF)
        return struct.pack('!Q', idx) + b'\x00\x00\x00\x00'

    def send_fragments(compressed):
        nonlocal seq, ts, roc
        MTU = RTP_MTU
        chunks = [compressed[i:i+MTU] for i in range(0, len(compressed), MTU)]
        total  = len(chunks)
        for frag_idx, chunk in enumerate(chunks):
            is_last = (frag_idx == total - 1)
            # Build frag header (8 bytes): magic(2) seq(2) frag_idx(1) total(1) reserved(2)
            frag_hdr = struct.pack('!HHBBH', FRAG_MAGIC, seq & 0xFFFF, frag_idx, total, 0)
            payload  = frag_hdr + chunk
            # RTP header (12 bytes)
            byte0  = 0x80
            byte1  = (0x80 if is_last else 0) | 96   # marker on last, PT=96
            rtp_hdr = struct.pack('!BBHII', byte0, byte1, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
            nonce   = build_nonce(seq)
            enc     = cipher.encrypt(nonce, payload, rtp_hdr)
            sock.sendto(rtp_hdr + enc, (client_ipv6, client_port))
            seq += 1
            if seq > 0xFFFF:
                seq = 0; roc += 1
        ts = (ts + 3600) & 0xFFFFFFFF

    logging.info('RTP-TX: waiting for client registration...')
    rtp_ready.wait()
    logging.info(f'RTP-TX: streaming to [{client_ipv6}]:{client_port}')

    while True:
        try:
            batch = tx_queue.get_batch()
            if not batch:
                continue
            raw        = b''.join(struct.pack('!I', len(p)) + p for p in batch)
            compressed = cctx.compress(raw)
            send_fragments(compressed)
            stat_bytes += len(raw)
            now = time.monotonic()
            if now - stat_time >= 10:
                mbps = (stat_bytes * 8) / ((now - stat_time) * 1_000_000)
                logging.info(f'RTP-TX: {mbps:.2f} Mbps, client=[{client_ipv6}]')
                stat_bytes = 0; stat_time = now
        except Exception as e:
            logging.error(f'RTP-TX error: {e}')
            time.sleep(0.1)


# ── Unix socket server (receives from Haraka plugin) ───────────────────────────
async def handle_unix_conn(reader, writer, tun_fd):
    global client_ipv6, client_port
    try:
        data = bytearray()
        while True:
            chunk = await reader.read(131072)
            if not chunk: break
            data.extend(chunk)

            # Process complete frames: [4-byte len][payload]
            offset = 0
            written = 0
            while offset + 4 <= len(data):
                plen = struct.unpack_from('!I', data, offset)[0]
                if plen == 0 or plen > 131072:
                    logging.error(f'Unix socket: invalid plen {plen}, resetting conn')
                    return
                if offset + 4 + plen > len(data):
                    break  # need more data

                payload = data[offset + 4 : offset + 4 + plen]
                offset += 4 + plen

                if payload[:len(REG_MAGIC)] == REG_MAGIC:
                    try:
                        reg = json.loads(payload[len(REG_MAGIC):].decode())
                        client_ipv6 = reg['ipv6']
                        client_port = reg.get('rtp_port', RTP_PORT)
                        logging.info(f'REG: client IPv6=[{client_ipv6}]:{client_port}')
                        rtp_ready.set()
                    except Exception as e:
                        logging.error(f'REG parse error: {e}')
                else:
                    try:
                        os.write(tun_fd, payload)
                        written += 1
                    except OSError as e:
                        logging.debug(f'TUN write: {e}')

            if written:
                logging.debug(f'RX: wrote {written} pkts to TUN')

            # Keep incomplete frame data in buffer
            del data[:offset]

    except Exception as e:
        logging.error(f'Unix conn error: {e}')
    finally:
        writer.close()


async def unix_server(tun_fd):
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    server = await asyncio.start_unix_server(
        lambda r, w: handle_unix_conn(r, w, tun_fd),
        path=SOCK_PATH
    )
    os.chmod(SOCK_PATH, 0o777)
    logging.info(f'Unix socket ready: {SOCK_PATH}')
    async with server:
        await server.serve_forever()


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    logging.info('wl-server starting (Exit Node)')
    tun_fd = create_tun()

    threading.Thread(target=tun_reader, args=(tun_fd,), daemon=True, name='TUN-READ').start()
    threading.Thread(target=rtp_tx_thread, daemon=True, name='RTP-TX').start()

    asyncio.run(unix_server(tun_fd))


if __name__ == '__main__':
    main()