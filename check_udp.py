import paramiko, time

def connect(ip, pw):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username='root', password=pw, timeout=10)
    return ssh

def sftp_put_content(ssh, content, remote_path):
    sftp = ssh.open_sftp()
    with sftp.open(remote_path, 'w') as f:
        f.write(content)
    sftp.close()

def run(ssh, cmd, timeout=15):
    _, o, e = ssh.exec_command(cmd, timeout=timeout)
    out = o.read().decode().strip()
    err = e.read().decode().strip()
    return out, err

# Scripts
LISTENER = """
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.settimeout(8)
s.bind('::', 10080)
print('READY', flush=True)
try:
    data, addr = s.recvfrom(1024)
    print(f'GOT {len(data)}b FROM {addr[0]}', flush=True)
except socket.timeout:
    print('TIMEOUT - no data received', flush=True)
s.close()
"""

LISTENER = """
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.settimeout(8)
s.bind(('::', 10080))
print('READY', flush=True)
try:
    data, addr = s.recvfrom(1024)
    print('GOT ' + str(len(data)) + 'b FROM ' + str(addr[0]), flush=True)
except socket.timeout:
    print('TIMEOUT - no data received', flush=True)
s.close()
"""

SENDER_UDP = """
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.sendto(b'WLVPN-TEST-123', ('2a00:b700:5::3:3cf', 10080))
print('SENT OK', flush=True)
s.close()
"""

SENDER_TCP = """
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('2a00:b700:5::3:3cf', 10080))
    s.send(b'WLVPN-TCP-TEST')
    print('TCP SENT OK', flush=True)
    s.close()
except Exception as e:
    print('TCP FAIL: ' + str(e), flush=True)
"""

LISTENER_TCP = """
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(('::', 10080))
s.listen(1)
s.settimeout(8)
print('TCP READY', flush=True)
try:
    c, addr = s.accept()
    data = c.recv(1024)
    print('TCP GOT ' + str(len(data)) + 'b FROM ' + str(addr[0]), flush=True)
    c.close()
except socket.timeout:
    print('TCP TIMEOUT', flush=True)
s.close()
"""

rus2 = connect('46.29.164.96',  '7u3w6EjE6w1iFvL')
mp80 = connect('100.68.139.8',  '1arabyan3G!')

# Upload scripts
sftp_put_content(rus2, LISTENER,     '/tmp/wl_listen_udp.py')
sftp_put_content(rus2, LISTENER_TCP, '/tmp/wl_listen_tcp.py')
sftp_put_content(mp80, SENDER_UDP,   '/tmp/wl_send_udp.py')
sftp_put_content(mp80, SENDER_TCP,   '/tmp/wl_send_tcp.py')
print("Scripts uploaded.")

# Ensure firewall open on RUS2
run(rus2, 'ip6tables -I INPUT -p udp --dport 10080 -j ACCEPT 2>/dev/null')
run(rus2, 'iptables  -I INPUT -p udp --dport 10080 -j ACCEPT 2>/dev/null')
run(rus2, 'ip6tables -I INPUT -p tcp --dport 10080 -j ACCEPT 2>/dev/null')

# --- TEST 1: UDP ---
print("\n=== TEST 1: UDP IPv6 MP80 -> RUS2 ===")
_, o_udp, _ = rus2.exec_command('python3 /tmp/wl_listen_udp.py')
time.sleep(1.5)

o, e = run(mp80, 'python3 /tmp/wl_send_udp.py', timeout=5)
print(f"MP80 UDP send: {o or e}")

time.sleep(5)
udp_result = o_udp.read().decode().strip()
print(f"RUS2 UDP recv: {udp_result}")

udp_ok = 'GOT' in udp_result

# --- TEST 2: TCP fallback ---
print("\n=== TEST 2: TCP IPv6 MP80 -> RUS2 ===")
_, o_tcp, _ = rus2.exec_command('python3 /tmp/wl_listen_tcp.py')
time.sleep(1.5)

o, e = run(mp80, 'python3 /tmp/wl_send_tcp.py', timeout=8)
print(f"MP80 TCP send: {o or e}")

time.sleep(5)
tcp_result = o_tcp.read().decode().strip()
print(f"RUS2 TCP recv: {tcp_result}")

tcp_ok = 'GOT' in tcp_result

# --- SUMMARY ---
print("\n========= RESULTS =========")
print(f"UDP IPv6 MP80->RUS2: {'OK' if udp_ok else 'BLOCKED'}")
print(f"TCP IPv6 MP80->RUS2: {'OK' if tcp_ok else 'BLOCKED'}")

if udp_ok:
    print("\nRTP channel (UDP) is viable!")
elif tcp_ok:
    print("\nOnly TCP works - need to use TCP-based RX or QUIC/WebSocket")
else:
    print("\nBoth blocked - ISP filters incoming IPv6 on RUS2")

mp80.close()
rus2.close()
