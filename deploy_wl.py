#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# deploy_wl.py — Deploy wl-vpn to MP80 (Israel) and RUS2 (Russia)
# Reads config from .env and config.yaml — NEVER hardcode secrets!

import os
import sys
import yaml
import paramiko
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Load configuration
# ─────────────────────────────────────────────────────────────────────────────
def load_env(env_path: Path) -> dict:
    """Load .env file into dict."""
    if not env_path.exists():
        return {}
    data = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        data[k.strip()] = v.strip().strip('"\'')
    return data


def load_yaml(yaml_path: Path) -> dict:
    """Load YAML config."""
    if not yaml_path.exists():
        return {}
    return yaml.safe_load(yaml_path.read_text()) or {}


# Load configs
ROOT = Path(__file__).parent
ENV = load_env(ROOT / '.env')
CFG = load_yaml(ROOT / 'config.yaml')

# Merge: env overrides yaml for deployment section
DEPLOY = CFG.get('deploy', {})
MP80_CFG = DEPLOY.get('mp80', {})
RUS2_CFG = DEPLOY.get('rus2', {})

# ─────────────────────────────────────────────────────────────────────────────
# Resolve values (env > yaml > defaults)
# ─────────────────────────────────────────────────────────────────────────────
def get(key: str, default: str = '') -> str:
    """Get from ENV, then CFG, then default."""
    return ENV.get(key) or str(CFG.get(key, default))


# Required values — will error if missing
MP80_IP = get('MP80_IP') or MP80_CFG.get('host') or ''
MP80_PW = get('MP80_PASSWORD') or ''
RUS2_IP = get('RUS2_IP') or RUS2_CFG.get('host') or ''
RUS2_PW = get('RUS2_PASSWORD') or ''
MP80_IPV6 = get('MP80_IPV6') or ''
RTP_PORT = int(get('RTP_PORT') or CFG.get('client', {}).get('rtp_port', 10080))
SMTP_PORT = int(get('SMTP_PORT') or CFG.get('client', {}).get('smtp_port', 2525))
PSK_HEX = get('PSK_HEX') or CFG.get('crypto', {}).get('psk_hex', '')

HARAKA_PLUGINS_DIR = get('HARAKA_PLUGINS_DIR') or MP80_CFG.get('haraka_plugins_dir', '/usr/local/haraka/plugins')
HARAKA_CONFIG_PLUGINS = MP80_CFG.get('haraka_config_plugins', '/usr/local/haraka/config/plugins')

SERVICE_CLIENT = get('SERVICE_CLIENT', 'wl-client')
SERVICE_SERVER = get('SERVICE_SERVER', 'wl-server')
HARAKA_SERVICE = get('HARAKA_SERVICE', 'haraka_v10')

# Validate required
missing = []
for name, val in [('MP80_IP', MP80_IP), ('MP80_PASSWORD', MP80_PW),
                  ('RUS2_IP', RUS2_IP), ('RUS2_PASSWORD', RUS2_PW),
                  ('MP80_IPV6', MP80_IPV6), ('PSK_HEX', PSK_HEX)]:
    if not val:
        missing.append(name)

if missing:
    print(f"❌ Missing required config: {', '.join(missing)}")
    print("   Create .env from .env.example and fill in values")
    sys.exit(1)

# Validate PSK
if len(PSK_HEX) != 64:
    print(f"❌ PSK_HEX must be 64 hex chars (32 bytes), got {len(PSK_HEX)}")
    sys.exit(1)

try:
    PSK = bytes.fromhex(PSK_HEX)
except ValueError:
    print("❌ PSK_HEX must be valid hex")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def connect(ip: str, pw: str, user: str = 'root', key_path: str = None) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if key_path and os.path.exists(key_path):
        ssh.connect(ip, username=user, key_filename=key_path, timeout=15)
    else:
        ssh.connect(ip, username=user, password=pw, timeout=15)
    print(f'  Connected to {ip}')
    return ssh


def run(ssh: paramiko.SSHClient, cmd: str, check: bool = False, timeout: int = 60) -> tuple[str, str]:
    _, o, e = ssh.exec_command(cmd, timeout=timeout)
    out = o.read().decode().strip()
    err = e.read().decode().strip()
    if out:
        print(f'    > {out[:300]}')
    if err and 'npm WARN' not in err and 'Warning' not in err and 'warning' not in err.lower():
        print(f'    ! {err[:300]}')
    if check and err:
        raise RuntimeError(f'Command failed: {cmd}\n{err}')
    return out, err


def upload(ssh: paramiko.SSHClient, local: str, remote: str):
    sftp = ssh.open_sftp()
    sftp.put(local, remote)
    sftp.close()
    print(f'    uploaded {os.path.basename(local)} -> {remote}')


def write_remote(ssh: paramiko.SSHClient, content: str, remote: str):
    sftp = ssh.open_sftp()
    with sftp.open(remote, 'w') as f:
        f.write(content)
    sftp.close()
    print(f'    wrote {remote}')


# ─────────────────────────────────────────────────────────────────────────────
# Systemd units (templated) — with log rate limiting to prevent disk fill
# ─────────────────────────────────────────────────────────────────────────────
SYSTEMD_SERVER = f"""[Unit]
Description=wl-vpn Exit Node
After=network.target {HARAKA_SERVICE}.service
Requires={HARAKA_SERVICE}.service

[Service]
ExecStart=/usr/bin/python3 /root/wl-server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
# Rate limit logs to prevent disk fill (max 1000 msg/10s per service)
LogRateLimitIntervalSec=10
LogRateLimitBurst=1000
# Python log level: DEBUG, INFO, WARNING, ERROR
Environment=LOG_LEVEL=INFO
# Python internal rate limit (seconds between same message), 0 = off
Environment=LOG_RATE_LIMIT=5
Environment=PSK_HEX={PSK_HEX}
Environment=RTP_PORT={RTP_PORT}
Environment=SMTP_PORT={SMTP_PORT}

[Install]
WantedBy=multi-user.target
"""

SYSTEMD_CLIENT = f"""[Unit]
Description=wl-vpn Client
After=network.target

[Service]
ExecStart=/usr/bin/python3 /root/wl-client.py {MP80_IPV6}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=10
LogRateLimitBurst=1000
Environment=LOG_LEVEL=INFO
Environment=LOG_RATE_LIMIT=5
Environment=PSK_HEX={PSK_HEX}
Environment=RTP_PORT={RTP_PORT}
Environment=SMTP_PORT={SMTP_PORT}

[Install]
WantedBy=multi-user.target
"""

# ─────────────────────────────────────────────────────────────────────────────
# Log rotation & journald limits — CRITICAL to prevent disk fill
# ─────────────────────────────────────────────────────────────────────────────
LOGROTATE_CONF = """# wl-vpn log rotation — prevents disk fill
/var/log/wl-*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root root
    maxsize 100M
    size 50M
}
"""

JOURNALD_CONF = """# journald limits — prevents disk fill from systemd logs
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=100M
SystemMaxFiles=10
RuntimeMaxUse=200M
RuntimeMaxFileSize=50M
RuntimeMaxFiles=5
MaxRetentionSec=7day
MaxFileSec=1day
ForwardToSyslog=no
"""

def setup_log_limits(ssh: paramiko.SSHClient, label: str):
    """Configure logrotate and journald to prevent disk exhaustion."""
    print(f'  Configuring log limits on {label}...')
    # journald.conf.d
    run(ssh, 'mkdir -p /etc/systemd/journald.conf.d')
    write_remote(ssh, JOURNALD_CONF, '/etc/systemd/journald.conf.d/99-wl-vpn.conf')
    # logrotate
    write_remote(ssh, LOGROTATE_CONF, '/etc/logrotate.d/wl-vpn')
    # Restart journald
    run(ssh, 'systemctl restart systemd-journald 2>/dev/null || true')
    print(f'  Log limits configured on {label}')


# ─────────────────────────────────────────────────────────────────────────────
# Deploy MP80 (Exit Node / Israel)
# ─────────────────────────────────────────────────────────────────────────────
def deploy_mp80():
    print('\n=== Deploying to MP80 (Israel / Exit Node) ===')
    ssh = connect(MP80_IP, MP80_PW)

    # CRITICAL: Configure log limits FIRST to prevent disk fill
    setup_log_limits(ssh, 'MP80')

    # Upload server code
    upload(ssh, 'wl-server.py', '/root/wl-server.py')
    upload(ssh, 'tunnel_wl_receiver.js', f'{HARAKA_PLUGINS_DIR}/tunnel_wl_receiver.js')

    # Switch Haraka to wl plugin
    run(ssh, f'echo "tunnel_wl_receiver" > {HARAKA_CONFIG_PLUGINS}')

    # Open UDP 10080 outbound (RTP sender)
    for proto in ['ip6tables', 'iptables']:
        run(ssh, f'{proto} -D OUTPUT -p udp --dport {RTP_PORT} -j ACCEPT 2>/dev/null; '
                 f'{proto} -I OUTPUT -p udp --dport {RTP_PORT} -j ACCEPT')

    # Install python deps
    deps = ' '.join(MP80_CFG.get('python_deps', ['zstandard', 'cryptography']))
    run(ssh, f'pip3 install {deps} --quiet 2>/dev/null || '
             f'pip3 install {deps} --break-system-packages --quiet 2>/dev/null')

    # Write systemd service
    write_remote(ssh, SYSTEMD_SERVER, f'/etc/systemd/system/{SERVICE_SERVER}.service')

    run(ssh, 'systemctl daemon-reload')
    run(ssh, f'systemctl stop {SERVICE_SERVER} 2>/dev/null; systemctl stop {HARAKA_SERVICE} 2>/dev/null; sleep 2')
    run(ssh, f'systemctl start {HARAKA_SERVICE} && sleep 3 && systemctl start {SERVICE_SERVER}')
    run(ssh, f'systemctl enable {SERVICE_SERVER} {HARAKA_SERVICE} 2>/dev/null')

    time.sleep(3)
    out, _ = run(ssh, f'systemctl is-active {SERVICE_SERVER} {HARAKA_SERVICE}')
    print(f'  MP80 services: {out}')
    ssh.close()
    print('  MP80 deploy OK')


# ─────────────────────────────────────────────────────────────────────────────
# Deploy RUS2 (Client / Russia)
# ─────────────────────────────────────────────────────────────────────────────
def deploy_rus2():
    print('\n=== Deploying to RUS2 (Russia / Client) ===')
    ssh = connect(RUS2_IP, RUS2_PW)

    # CRITICAL: Configure log limits FIRST to prevent disk fill
    setup_log_limits(ssh, 'RUS2')

    # Upload client code
    upload(ssh, 'wl-client.py', '/root/wl-client.py')

    # Open UDP 10080 inbound (RTP receiver)
    for proto in ['ip6tables', 'iptables']:
        run(ssh, f'{proto} -D INPUT -p udp --dport {RTP_PORT} -j ACCEPT 2>/dev/null; '
                 f'{proto} -I INPUT -p udp --dport {RTP_PORT} -j ACCEPT')

    # Install python deps
    deps = ' '.join(RUS2_CFG.get('python_deps', ['zstandard', 'cryptography']))
    run(ssh, f'pip3 install {deps} --quiet 2>/dev/null || '
             f'pip3 install {deps} --break-system-packages --quiet 2>/dev/null')

    # Write systemd service (target is MP80 IPv6)
    write_remote(ssh, SYSTEMD_CLIENT, f'/etc/systemd/system/{SERVICE_CLIENT}.service')

    run(ssh, 'systemctl daemon-reload')
    run(ssh, f'systemctl stop {SERVICE_CLIENT} 2>/dev/null; sleep 1')
    run(ssh, f'systemctl start {SERVICE_CLIENT}')
    run(ssh, f'systemctl enable {SERVICE_CLIENT} 2>/dev/null')

    time.sleep(5)
    out, _ = run(ssh, f'systemctl is-active {SERVICE_CLIENT}')
    print(f'  RUS2 {SERVICE_CLIENT}: {out}')

    # Check logs
    run(ssh, f'journalctl -u {SERVICE_CLIENT} -n 20 --no-pager 2>/dev/null')
    ssh.close()
    print('  RUS2 deploy OK')


# ─────────────────────────────────────────────────────────────────────────────
# E2E check
# ─────────────────────────────────────────────────────────────────────────────
def e2e_check():
    print('\n=== E2E Check ===')
    ssh = connect(RUS2_IP, RUS2_PW)
    time.sleep(5)

    # Check if wltun0 is up
    out, _ = run(ssh, 'ip addr show wltun0 2>/dev/null | head -5')
    if 'wltun0' in out:
        print('  ✅ wltun0 UP on RUS2')
    else:
        print('  ❌ wltun0 NOT UP on RUS2 — check logs')

    # Check RTP logs
    out, _ = run(ssh, f'journalctl -u {SERVICE_CLIENT} -n 30 --no-pager 2>/dev/null | grep -E "RTP|REG|error|Error"')
    print(f'  Client logs:\n{out or "(empty)"}')

    ssh_mp80 = connect(MP80_IP, MP80_PW)
    out, _ = run(ssh_mp80, f'journalctl -u {SERVICE_SERVER} -n 20 --no-pager 2>/dev/null | grep -E "REG|RTP|error|Error"')
    print(f'  Server logs:\n{out or "(empty)"}')

    # Ping test
    out, _ = run(ssh, 'ping -c3 -W2 10.0.200.2 2>&1 | tail -3')
    print(f'  ping 10.0.200.2: {out}')

    ssh.close()
    ssh_mp80.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'all'

    if cmd in ('all', 'mp80'):
        deploy_mp80()
    if cmd in ('all', 'rus2'):
        deploy_rus2()
    if cmd in ('all', 'check'):
        print('\nWaiting 10s for tunnel to establish...')
        time.sleep(10)
        e2e_check()

    print('\n✅ Deploy complete.')