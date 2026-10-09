#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# config_loader.py — Load configuration from environment variables
# Used by wl-client.py and wl-server.py

import os
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def get_env(key: str, default: str = '') -> str:
    """Get env var with default."""
    return os.environ.get(key, default)


def get_env_int(key: str, default: int) -> int:
    """Get env var as int with default."""
    val = os.environ.get(key)
    return int(val) if val is not None else default


def get_env_bool(key: str, default: bool = False) -> bool:
    """Get env var as bool with default."""
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ('1', 'true', 'yes', 'on')


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


# ROC persistence
ROC_STATE_DIR = Path(get_env('ROC_STATE_DIR', '/var/lib/wl-vpn'))
ROC_STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_roc_state(role: str) -> dict:
    """Load ROC/seq state from disk for restart resilience."""
    path = ROC_STATE_DIR / f'roc_{role}.json'
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {'roc': 0, 'seq': 0}


def save_roc_state(role: str, roc: int, seq: int):
    """Save ROC/seq state to disk."""
    path = ROC_STATE_DIR / f'roc_{role}.json'
    try:
        path.write_text(json.dumps({'roc': roc, 'seq': seq}))
    except Exception:
        pass  # best effort


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

    # Crypto keys (separate per direction)
    'rtp_key_rx': derive_key(get_env('RTP_KEY_LABEL_RX', 'wl-vpn-rtp-server-to-client').encode()),
    'rtp_key_tx': derive_key(get_env('RTP_KEY_LABEL_TX', 'wl-vpn-rtp-client-to-server').encode()),
    'reg_auth_key': derive_key(b'wl-vpn-registration-auth'),

    # ROC persistence
    'roc_state': load_roc_state('client'),

    # RTP recovery
    'rtp_recovery_enabled': get_env_bool('RTP_RECOVERY_ENABLED', True),
    'rtp_recovery_interval': get_env_int('RTP_RECOVERY_INTERVAL', 30),
    'rtp_probe_interval': get_env_int('RTP_PROBE_INTERVAL', 10),
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

    # Crypto keys (separate per direction)
    'rtp_key_rx': derive_key(get_env('RTP_KEY_LABEL_RX', 'wl-vpn-rtp-client-to-server').encode()),
    'rtp_key_tx': derive_key(get_env('RTP_KEY_LABEL_TX', 'wl-vpn-rtp-server-to-client').encode()),
    'reg_auth_key': derive_key(b'wl-vpn-registration-auth'),

    # ROC persistence
    'roc_state': load_roc_state('server'),

    # RTP recovery
    'rtp_recovery_enabled': get_env_bool('RTP_RECOVERY_ENABLED', True),
    'rtp_client_timeout': get_env_int('RTP_CLIENT_TIMEOUT', 60),
}


def get_client_config() -> dict:
    return CLIENT_CFG.copy()


def get_server_config() -> dict:
    return SERVER_CFG.copy()