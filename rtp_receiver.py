#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rtp_receiver.py — PoC RTP receiver (Client / Russia side)

Receives RTP packets, decrypts, measures throughput/latency/loss/jitter.
Simulates watching a 4K IP camera stream.

Usage: python3 rtp_receiver.py [port]
"""

import socket
import struct
import time
import sys
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logging.warning("cryptography not installed — using XOR obfuscation fallback")


class SRTPDecryptor:
    """SRTP-compatible decryption."""

    def __init__(self, key: bytes):
        self.key = key
        if HAS_CRYPTO:
            self.cipher = ChaCha20Poly1305(key)
        self.roc = 0

    def decrypt(self, seq: int, rtp_header: bytes, ciphertext: bytes) -> bytes:
        nonce = self._build_nonce(seq)
        if HAS_CRYPTO:
            try:
                return self.cipher.decrypt(nonce, ciphertext, rtp_header)
            except Exception:
                return None  # auth failed
        else:
            key_stream = hashlib.sha256(nonce + self.key).digest()
            return bytes(b ^ key_stream[i % 32] for i, b in enumerate(ciphertext))

    def _build_nonce(self, seq: int) -> bytes:
        idx = (self.roc << 32) | (seq & 0xFFFFFFFF)
        return struct.pack('!Q', idx) + b'\x00\x00\x00\x00'


class ReplayWindow:
    """Sliding window replay protection."""

    def __init__(self, size=2048):
        self.size = size
        self.bitmap = 0
        self.max_seq = 0

    def check(self, seq: int) -> bool:
        if seq > self.max_seq:
            shift = min(seq - self.max_seq, self.size)
            self.bitmap <<= shift
            self.bitmap |= 1
            self.bitmap &= (1 << self.size) - 1
            self.max_seq = seq
            return True

        delta = self.max_seq - seq
        if delta >= self.size:
            return False  # too old
        if self.bitmap & (1 << delta):
            return False  # replay
        self.bitmap |= (1 << delta)
        return True


def parse_rtp_header(data: bytes):
    """Parse 12-byte RTP header. Returns (version, pt, seq, ts, ssrc, payload)."""
    if len(data) < 12:
        return None
    b0, b1, seq, ts, ssrc = struct.unpack('!BBHII', data[:12])
    version = (b0 >> 6) & 3
    marker = bool(b1 & 0x80)
    pt = b1 & 0x7F
    return {
        'version': version,
        'marker': marker,
        'pt': pt,
        'seq': seq,
        'ts': ts,
        'ssrc': ssrc,
        'payload': data[12:],
    }


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 10080

    # Pre-shared key (must match sender)
    PSK = hashlib.sha256(b'wl-vpn-poc-key-2024').digest()

    # Bind on all interfaces (IPv6 + IPv4)
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(('::', port))
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', port))

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)

    decryptor = SRTPDecryptor(PSK)
    replay = ReplayWindow()

    logging.info(f"RTP receiver listening on :{port}")
    logging.info(f"Crypto: {'ChaCha20-Poly1305' if HAS_CRYPTO else 'XOR fallback'}")
    logging.info("Waiting for packets...")

    # Stats
    stat_bytes = 0
    stat_pkts = 0
    stat_decrypt_ok = 0
    stat_decrypt_fail = 0
    stat_replay = 0
    stat_time = time.monotonic()
    last_seq = None
    total_lost = 0
    total_received = 0
    latencies = []
    jitters = []
    last_arrival = None
    last_rtp_ts = None
    source_addr = None

    try:
        while True:
            data, addr = sock.recvfrom(65535)

            if source_addr is None:
                source_addr = addr
                logging.info(f"First packet from: {addr[0]}:{addr[1]}")

            stat_bytes += len(data)
            stat_pkts += 1
            total_received += 1

            # Parse RTP header
            rtp = parse_rtp_header(data)
            if rtp is None or rtp['version'] != 2:
                continue

            rtp_header = data[:12]
            encrypted_payload = data[12:]

            # Replay check
            full_seq = rtp['seq']  # TODO: handle ROC for full 48-bit index
            if not replay.check(full_seq):
                stat_replay += 1
                continue

            # Decrypt
            plaintext = decryptor.decrypt(full_seq, rtp_header, encrypted_payload)
            if plaintext is None:
                stat_decrypt_fail += 1
                continue
            stat_decrypt_ok += 1

            # Packet loss detection
            if last_seq is not None:
                expected = (last_seq + 1) & 0xFFFF
                if full_seq != expected:
                    gap = (full_seq - expected) & 0xFFFF
                    if gap < 1000:  # reasonable gap
                        total_lost += gap
            last_seq = full_seq

            # Latency measurement (if payload has timestamp)
            if len(plaintext) >= 16:
                try:
                    _, _, send_time = struct.unpack('!IId', plaintext[:16])
                    latency_ms = (time.time() - send_time) * 1000
                    if -5000 < latency_ms < 5000:  # sanity check
                        latencies.append(latency_ms)
                except struct.error:
                    pass

            # Jitter calculation (RFC 3550)
            arrival = time.monotonic()
            if last_arrival is not None and last_rtp_ts is not None:
                transit_diff = abs(
                    (arrival - last_arrival) -
                    (rtp['ts'] - last_rtp_ts) / 90000.0
                )
                jitters.append(transit_diff * 1000)  # ms
            last_arrival = arrival
            last_rtp_ts = rtp['ts']

            # Stats every 5 seconds
            now = time.monotonic()
            elapsed = now - stat_time
            if elapsed >= 5.0:
                mbps = (stat_bytes * 8) / (elapsed * 1_000_000)
                pps = stat_pkts / elapsed

                loss_pct = (total_lost / max(1, total_received + total_lost)) * 100

                avg_lat = sum(latencies) / len(latencies) if latencies else 0
                min_lat = min(latencies) if latencies else 0
                max_lat = max(latencies) if latencies else 0

                avg_jit = sum(jitters[-100:]) / len(jitters[-100:]) if jitters else 0

                logging.info(
                    f"RX: {mbps:.2f} Mbps | {pps:.0f} pps | "
                    f"loss: {total_lost}/{total_received + total_lost} ({loss_pct:.1f}%) | "
                    f"latency: {avg_lat:.1f}ms (min={min_lat:.1f} max={max_lat:.1f}) | "
                    f"jitter: {avg_jit:.2f}ms | "
                    f"decrypt_ok={stat_decrypt_ok} fail={stat_decrypt_fail} replay={stat_replay}"
                )

                stat_bytes = 0
                stat_pkts = 0
                stat_decrypt_ok = 0
                stat_decrypt_fail = 0
                stat_replay = 0
                stat_time = now
                latencies.clear()

    except KeyboardInterrupt:
        logging.info(f"\nFinal stats:")
        logging.info(f"  Total received: {total_received}")
        logging.info(f"  Total lost: {total_lost}")
        loss_pct = (total_lost / max(1, total_received + total_lost)) * 100
        logging.info(f"  Loss rate: {loss_pct:.2f}%")
        logging.info("Stopped.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
