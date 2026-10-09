import paramiko, time

def diag(ip, pw, label):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username='root', password=pw, timeout=10)
    print(f"\n{'='*40}\n{label} ({ip})\n{'='*40}")

    cmds = {
        'IPv6 addresses':     'ip -6 addr show',
        'IPv6 routes':        'ip -6 route | head -10',
        'ip6tables INPUT':    'ip6tables -L INPUT -n -v --line-numbers 2>/dev/null || echo n/a',
        'iptables INPUT':     'iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -20',
        'netstat UDP':        'ss -ulnp | head -10',
        'Haraka ports':       'ss -tlnp | grep -E "25|587|2525|465" | head -5',
    }

    for name, cmd in cmds.items():
        _, o, _ = ssh.exec_command(cmd)
        out = o.read().decode().strip()
        print(f"\n[{name}]\n{out if out else '(empty)'}")

    ssh.close()

diag('46.29.164.96',  '7u3w6EjE6w1iFvL', 'RUS2 (Russia)')
diag('100.68.139.8',  '1arabyan3G!',      'MP80 (Israel)')
