import paramiko, sys
sys.stdout.reconfigure(encoding='utf-8')

def check(ip, pw, label, cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username='root', password=pw, timeout=10)
    print(f'\n=== {label} ===')
    _, o, _ = ssh.exec_command(cmd)
    print(o.read().decode())
    ssh.close()

# Check wl-server for REG messages
check('100.68.139.8', '1arabyan3G!', 'MP80 wl-server all logs',
      'journalctl -u wl-server -n 60 --no-pager 2>/dev/null')

# Check if unix socket exists and wl-server is listening
check('100.68.139.8', '1arabyan3G!', 'MP80 unix socket check',
      'ls -la /tmp/wl_tun.sock 2>/dev/null && ss -xl | grep wl_tun')

# Check what haraka actually sends to socket
check('100.68.139.8', '1arabyan3G!', 'MP80 haraka plugin errors',
      'journalctl -u haraka_v10 --since "2026-05-21 08:00:00" --no-pager 2>/dev/null | grep -E "wl|error|Error|sock" | head -20')

# Check wl-client REG sending
check('46.29.164.96', '7u3w6EjE6w1iFvL', 'RUS2 REG logs',
      'journalctl -u wl-client --since "2026-05-20 22:18:00" --until "2026-05-20 22:25:00" --no-pager 2>/dev/null | grep -E "REG|SMTP|error|Error|connect"')
