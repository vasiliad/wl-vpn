import paramiko, sys

def check(ip, pw):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username='root', password=pw, timeout=10)
    
    cmds = [
        'python3 -c "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305; print(\'crypto: OK\')" 2>&1 || echo "crypto: MISSING"',
        'ip -6 addr show scope global 2>/dev/null | grep inet6 | head -3',
        'ping6 -c1 -W3 2a00:a041:e442:7100:215:5dff:fe00:200 2>&1 | tail -1' if '46.' in ip else 'ping6 -c1 -W3 2a00:b700:5::3:3cf 2>&1 | tail -1',
    ]
    
    print(f"\n=== {ip} ===")
    for cmd in cmds:
        _, o, e = ssh.exec_command(cmd)
        out = o.read().decode().strip()
        err = e.read().decode().strip()
        if out: print(out)
        if err and 'WARNING' not in err: print(f"  err: {err}")
    ssh.close()

check('46.29.164.96', '7u3w6EjE6w1iFvL')
check('100.68.139.8', '1arabyan3G!')
