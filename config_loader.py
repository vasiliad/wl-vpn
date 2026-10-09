#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# config_loader.py — Load configuration from environment variables
# Used by wl-client.py and wl-server.py

import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def get_env(key: str, default: str = '') -> str:
    """Get env var with default."""
    return os.environ.get(key, default)


def get_env_int(key: str, default: int) -> int:
    """Get env var as int with default."""
    val = os.environ.get(key)
    return int(val) if val is not None else default


def load_psk() -> bytes:
    """Load PSK from PSK_HEX env var (64 hex chars = 32 bytes)."""
    psk_hex = get_env('PSK_HEX')
    if not psk_hex:
        # Fallback for backwards compatibility (hardcoded)
        return hashlib.sha256(b'wl-vpn-shared-secret-2024').digest()
    if len(psk_hex) != 64:
        raise ValueError(f'PSK_HEX must be 64 hex chars, got {len(psk_hex)}')
    return bytes.fromhex(psk_hex)


PSK = load_psk()


def derive_key(label: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label)
    return hkdf.derive(PSK)


# ── Client config ─────────────────────────────────────────────────────────────
CLIENT_CFG = {
    'tun_dev': get_env('TUN_DEV', 'wltun0'),
    'tun_ip': get_env('TUN_IP', '10.0.200.1/30'),
    'tun_gw': get_env('TUN_GW', '10.0.200.2'),
    'smtp_port': get_env_int('SMTP_PORT', 2525),
    'rtp_port': get_env_int('RTP_PORT', 10080),
    'reg_magic': bytes.fromhex(get_env('REG_MAGIC', '00574c2d52454700')),
    'frag_magic': int(get_env('FRAG_MAGIC', '574c'), 16),
    'ack_threshold': get_env_int('ACK_THRESHOLD', 120),
    'max_batch_pkts': get_env_int('MAX_BATCH_PKTS', 200),
    'max_batch_bytes': get_env_int('MAX_BATCH_BYTES', 65536),
    'tx_streams': get_env_int('TX_STREAMS', 8),
    'batch_ms_max': get_env_int('BATCH_MS_MAX', 80) / 1000.0,
    'batch_ms_min': get_env_int('BATCH_MS_MIN', 2) / 1000.0,
    'rtp_timeout': get_env_int('RTP_TIMEOUT', 10),
    'rtp_key': derive_key(get_env('RTP_KEY_LABEL', 'wl-vpn-rtp-server-to-client').encode()),
}

# ── Server config ─────────────────────────────────────────────────────────────
SERVER_CFG = {
    'tun_dev': get_env('TUN_DEV', 'wltun0'),
    'tun_ip': get_env('TUN_IP', '10.0.200.2/30'),
    'tun_gw': get_env('TUN_GW', '10.0.200.1'),
    'sock_path': get_env('SOCK_PATH', '/tmp/wl_tun.sock'),
    'rtp_port': get_env_int('RTP_PORT', 10080),
    'reg_magic': bytes.fromhex(get_env('REG_MAGIC', '00574c2d52454700')),
    'frag_magic': int(get_env('FRAG_MAGIC', '574c'), 16),
    'ack_threshold': get_env_int('ACK_THRESHOLD', 120),
    'max_batch_pkts': get_env_int('MAX_BATCH_PKTS', 200),
    'max_batch_bytes': get_env_int('MAX_BATCH_BYTES', 65536),
    'batch_ms_max': get_env_int('BATCH_MS_MAX', 50) / 1000.0,
    'batch_ms_min': get_env_int('BATCH_MS_MIN', 2) / 1000.0,
    'rtp_mtu': get_env_int('RTP_MTU', 1200),
    'rtp_key': derive_key(get_env('RTP_KEY_LABEL', 'wl-vpn-rtp-server-to-client').encode()),
}


def get_client_config() -> dict:
    return CLIENT_CFG.copy()


def get_server_config() -> dict:
    return SERVER_CFG.copy()