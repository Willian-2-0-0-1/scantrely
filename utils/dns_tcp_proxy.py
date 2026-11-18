#!/usr/bin/env python3
"""
DNS UDP→TCP proxy.
Recebe queries UDP em 127.0.0.1:53, encaminha via TCP para upstream (8.8.8.8:53).
Necessário quando UDP porta 53 está bloqueado (ex: VMware NAT).
"""
import socket, struct, threading

UPSTREAM = ("8.8.8.8", 53)
LISTEN   = ("127.0.0.1", 53)

def forward(data, addr, sock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(5)
            tcp.connect(UPSTREAM)
            tcp.sendall(struct.pack("!H", len(data)) + data)
            raw_len = tcp.recv(2)
            if len(raw_len) < 2:
                return
            length = struct.unpack("!H", raw_len)[0]
            response = b""
            while len(response) < length:
                chunk = tcp.recv(length - len(response))
                if not chunk:
                    break
                response += chunk
            sock.sendto(response, addr)
    except Exception as e:
        print(f"[dns_proxy] error: {e}", flush=True)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(LISTEN)
    print(f"[dns_proxy] listening on {LISTEN[0]}:{LISTEN[1]} → {UPSTREAM[0]}:{UPSTREAM[1]} (TCP)", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=forward, args=(data, addr, sock), daemon=True).start()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
