#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rtp_sender.py — PoC RTP sender (Exit Node / Israel side)

Sends test data wrapped in RTP headers with ChaCha20-Poly1305 encryption.
Simulates a 4K IP camera stream.

Usage: python3 rtp_sender.py <client_ipv6> [port] [bitrate_mbps]
"""

import socket
import struct
import time
import sys
import os
import random
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# ---------------------------------------------------------------------------
# Crypto: ChaCha20-Poly1305 AEAD
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logging.warning("cryptography not installed — using XOR obfuscation fallback")


class SRTPEncryptor:
    """SRTP-compatible encryption using ChaCha20-Poly1305 or XOR fallback."""

    def __init__(self, key: bytes):
        self.key = key  # 32 bytes
        if HAS_CRYPTO:
            self.cipher = ChaCha20Poly1305(key)
        self.roc = 0  # rollover counter

    def encrypt(self, seq: int, rtp_header: bytes, payload: bytes) -> bytes:
        nonce = self._build_nonce(seq)
        if HAS_CRYPTO:
            return self.cipher.encrypt(nonce, payload, rtp_header)
        else:
            # XOR fallback for systems without cryptography lib
            key_stream = hashlib.sha256(nonce + self.key).digest()
            encrypted = bytes(b ^ key_stream[i % 32] for i, b in enumerate(payload))
            return encrypted

    def _build_nonce(self, seq: int) -> bytes:
        # 12-byte nonce: ROC (4B) + SEQ (4B) + padding (4B)
        idx = (self.roc << 32) | (seq & 0xFFFFFFFF)
        return struct.pack('!Q', idx) + b'\x00\x00\x00\x00'


# ---------------------------------------------------------------------------
# RTP Packet Builder
# ---------------------------------------------------------------------------
class RTPStream:
    """Builds valid RTP packets (RFC 3550) mimicking H.264 camera stream."""

    def __init__(self, ssrc=None):
        self.ssrc = ssrc or random.getrandbits(32)
        self.seq = random.randint(0, 65535)
        self.ts = random.randint(0, 2**32 - 1)
        self.frame_count = 0

    def build_packet(self, payload: bytes, marker: bool = False) -> tuple:
        """
        Returns (rtp_header, payload).
        marker=True on last packet of a frame.
        """
        byte0 = 0x80                             # V=2, P=0, X=0, CC=0
        byte1 = (0x80 if marker else 0) | 96     # M bit, PT=96 (H.264)

        header = struct.pack('!BBHII',
            byte0, byte1,
            self.seq & 0xFFFF,
            self.ts & 0xFFFFFFFF,
            self.ssrc,
        )
        self.seq += 1
        return header, payload

    def advance_frame(self):
        """Advance timestamp by one frame (25fps @ 90kHz clock = 3600 ticks)."""
        self.ts += 3600
        self.frame_count += 1

    def is_keyframe(self) -> bool:
        """Every 50th frame is a keyframe (GOP=2sec @ 25fps)."""
        return self.frame_count % 50 == 0


# ---------------------------------------------------------------------------
# Main sender
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: rtp_sender.py <client_ip> [port] [bitrate_mbps]")
        print("  client_ip:    IPv6 or IPv4 address of receiver")
        print("  port:         UDP port (default: 10080)")
        print("  bitrate_mbps: target bitrate in Mbps (default: 10)")
        sys.exit(1)

    client_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10080
    target_mbps = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0

    # Detect address family
    if ':' in client_ip:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    dest = (client_ip, port)

    # Pre-shared key (PoC only — in production, use ECDH exchange)
    PSK = hashlib.sha256(b'wl-vpn-poc-key-2024').digest()  # 32 bytes

    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    encryptor = SRTPEncryptor(PSK)
    stream = RTPStream()

    # Calculate timing
    payload_size = 1200  # bytes per RTP packet
    target_bps = target_mbps * 1_000_000
    target_pps = target_bps / (payload_size * 8)  # packets per second
    interval = 1.0 / target_pps if target_pps > 0 else 0.001
    pkts_per_frame = max(1, int(target_pps / 25))  # 25 fps

    logging.info(f"RTP sender → {client_ip}:{port}")
    logging.info(f"Target: {target_mbps:.1f} Mbps, ~{target_pps:.0f} pps, "
                 f"~{pkts_per_frame} pkts/frame, interval={interval*1000:.2f}ms")
    logging.info(f"SSRC: {stream.ssrc:#010x}")
    logging.info(f"Crypto: {'ChaCha20-Poly1305' if HAS_CRYPTO else 'XOR fallback'}")

    stat_bytes = 0
    stat_pkts = 0
    stat_time = time.monotonic()

    try:
        while True:
            # Generate one frame (25fps = 40ms per frame)
            frame_start = time.monotonic()

            for i in range(pkts_per_frame):
                is_last = (i == pkts_per_frame - 1)

                # Test payload: sequence number + timestamp + random fill
                test_data = struct.pack('!IId',
                    stream.seq, stream.frame_count,
                    time.time()  # for latency measurement
                )
                # Pad to payload_size
                padding_needed = payload_size - len(test_data)
                if padding_needed > 0:
                    test_data += os.urandom(padding_needed)

                # Build RTP
                rtp_header, payload = stream.build_packet(test_data, marker=is_last)

                # Encrypt
                encrypted = encryptor.encrypt(stream.seq - 1, rtp_header, payload)

                # Send
                try:
                    sock.sendto(rtp_header + encrypted, dest)
                    stat_bytes += len(rtp_header) + len(encrypted)
                    stat_pkts += 1
                except OSError as e:
                    logging.warning(f"Send error: {e}")

            stream.advance_frame()

            # Stats every 5 seconds
            now = time.monotonic()
            elapsed = now - stat_time
            if elapsed >= 5.0:
                mbps = (stat_bytes * 8) / (elapsed * 1_000_000)
                pps = stat_pkts / elapsed
                logging.info(f"TX: {mbps:.2f} Mbps, {pps:.0f} pps, "
                             f"frames={stream.frame_count}, seq={stream.seq & 0xFFFF}")
                stat_bytes = 0
                stat_pkts = 0
                stat_time = now

            # Frame pacing (25fps = 40ms)
            frame_elapsed = time.monotonic() - frame_start
            sleep_time = 0.040 - frame_elapsed  # 40ms per frame
            if sleep_time > 0:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        logging.info("Stopped.")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
