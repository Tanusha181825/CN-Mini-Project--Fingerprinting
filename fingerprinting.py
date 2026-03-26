import socket
import ssl
import threading
import time
from urllib.parse import urlparse

TIMEOUT = 2
lock = threading.Lock()


# -------------------------------
# Parse input
# -------------------------------
def parse_target(target):
    if not target.startswith("http"):
        target = "http://" + target
    return urlparse(target).hostname


# -------------------------------
# Resolve IP
# -------------------------------
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return "Resolution Failed"


# -------------------------------
# Receive data
# -------------------------------
def receive_full_data(sock):
    data = b""
    sock.settimeout(TIMEOUT)

    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass

    return data.decode(errors="ignore")


# -------------------------------
# TCP HTTP
# -------------------------------
def tcp_http(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, 80))

        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())

        res = receive_full_data(s)
        s.close()
        return res
    except Exception as e:
        return f"Error: {e}"


# -------------------------------
# TCP HTTPS + SSL
# FIX: Connect raw TCP first, THEN wrap for SSL.
# This avoids double-handshake overhead that inflated HTTPS time.
# -------------------------------
def tcp_https(host):
    try:
        context = ssl.create_default_context()

        # Step 1: raw TCP connect (no TLS yet)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(TIMEOUT)
        raw.connect((host, 443))          # <-- TCP connect on raw socket

        # Step 2: wrap for TLS (handshake happens here)
        secure = context.wrap_socket(raw, server_hostname=host)
        secure.settimeout(TIMEOUT)

        cert = secure.getpeercert()

        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        secure.send(req.encode())

        res = receive_full_data(secure)
        secure.close()

        return res, cert

    except Exception as e:
        return f"Error: {e}", None


# -------------------------------
# UDP Scan
# FIX: Removed the skip for IP input on port 53.
# 8.8.8.8 IS a DNS server — we should always send the query.
# For an IP target we build a minimal valid DNS query directly.
# -------------------------------
def udp_scan(host):
    results = []
    ports = [53, 123]  # DNS, NTP

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(TIMEOUT)

            start = time.time()

            if port == 53:
                # Build a minimal DNS query for "google.com" regardless of
                # whether the target is a hostname or a bare IP like 8.8.8.8.
                # Old code skipped this entirely for IPs — that was the bug.
                query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                domain = "google.com"
                for part in domain.split('.'):
                    query += bytes([len(part)]) + part.encode()
                query += b'\x00\x00\x01\x00\x01'
                sock.sendto(query, (host, port))

            elif port == 123:
                # NTP request
                sock.sendto(b'\x1b' + 47 * b'\0', (host, port))

            try:
                data, _ = sock.recvfrom(512)
                end = time.time()
                results.append(
                    f"Port {port}: UDP ✔ ({len(data)} bytes, {round(end - start, 2)} sec)"
                )
            except socket.timeout:
                results.append(f"Port {port}: No response (timeout)")

            sock.close()

        except Exception as e:
            results.append(f"Port {port}: Error ({e})")

    return results


# -------------------------------
# Extract server header
# -------------------------------
def extract_server(response):
    if not isinstance(response, str):
        return "Invalid"

    for line in response.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.strip()

    if "cloudflare" in response.lower():
        return "Server: Cloudflare (hidden)"

    return "Server not found"


# -------------------------------
# Identify server
# -------------------------------
def identify(response):
    if not isinstance(response, str):
        return "Unknown"

    r = response.lower()

    if "apache" in r:
        return "Apache"
    if "nginx" in r:
        return "Nginx"
    if "iis" in r:
        return "Microsoft IIS"
    if "cloudflare" in r:
        return "Cloudflare"
    if "gws" in r:
        return "Google Web Server"

    return "Unknown"


# -------------------------------
# Format SSL cert
# -------------------------------
def format_cert(cert):
    if not cert:
        return "No certificate"

    try:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        return (
            f"Issued To: {subject.get('commonName', 'N/A')}\n"
            f"Issued By: {issuer.get('commonName', 'N/A')}\n"
            f"Valid From: {cert.get('notBefore', 'N/A')}\n"
            f"Valid Till: {cert.get('notAfter', 'N/A')}"
        )
    except:
        return "Certificate parsing error"


# -------------------------------
# Scan
# -------------------------------
def scan(target):
    host = parse_target(target)
    ip = resolve_ip(host)

    print(f"\n Scanning {host}...")

    start_total = time.time()

    # HTTP
    h_start = time.time()
    http_res = tcp_http(host)
    h_time = round(time.time() - h_start, 2)

    # HTTPS
    s_start = time.time()
    https_res, cert = tcp_https(host)
    s_time = round(time.time() - s_start, 2)

    # UDP
    udp_results = udp_scan(host)

    end_total = time.time()

    with lock:
        print("\n" + "=" * 50)
        print(f"Target: {host} ({ip})")

        print("\n[TCP - HTTP]")
        print("Server:", extract_server(http_res))
        print("Identified:", identify(http_res))
        print(f" HTTP Time: {h_time} sec")

        print("\n[TCP - HTTPS]")
        print("Server:", extract_server(https_res))
        print("Identified:", identify(https_res))
        print(f" HTTPS Time: {s_time} sec")

        print("\n SSL Certificate:")
        print(format_cert(cert))

        print("\n[UDP Scan]")
        udp_supported = False
        for r in udp_results:
            print(r)
            if "✔" in r:
                udp_supported = True

        print("\n Protocol Analysis:")
        print("TCP: Supported")

        if udp_supported:
            print("UDP: Supported (response received)")
        else:
            print("UDP: Not confirmed / filtered")

        diff = round(s_time - h_time, 2)
        if diff >= 0:
            print(f"\n HTTPS slower than HTTP by {diff} sec (TLS handshake overhead)")
        else:
            print(f"\n HTTP slower than HTTPS by {abs(diff)} sec")

        print(f"\n Total Time: {round(end_total - start_total, 2)} sec")
        print("=" * 50)


# -------------------------------
# Main
# -------------------------------
def main():
    user_input = input("Enter URLs/IPs (comma separated): ")
    targets = [t.strip() for t in user_input.split(",")]

    threads = []

    for t in targets:
        th = threading.Thread(target=scan, args=(t,))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    print("\n Scan Completed")


# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    main()
