import socket
import ssl
import threading
import time

TIMEOUT = 3
lock = threading.Lock()


# -------------------------------
# Receive full response safely
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
# Retry wrapper (for reliability)
# -------------------------------
def retry(func, host, attempts=2):
    for _ in range(attempts):
        result = func(host)
        if not result.startswith("Error"):
            return result
    return result


# -------------------------------
# HTTP Banner Grabbing
# -------------------------------
def grab_http_banner(host, port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.send(request.encode())
        response = receive_full_data(s)
        s.close()

        return response

    except Exception as e:
        return f"Error: {e}"


# -------------------------------
# HTTPS Banner Grabbing (SSL)
# -------------------------------
def grab_https_banner(host, port=443):
    try:
        context = ssl.create_default_context()

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(TIMEOUT)

        secure_sock = context.wrap_socket(raw_sock, server_hostname=host)
        secure_sock.connect((host, port))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        secure_sock.send(request.encode())
        response = receive_full_data(secure_sock)
        secure_sock.close()

        return response

    except Exception as e:
        return f"Error: {e}"


# -------------------------------
# Extract Server Header + fallback
# -------------------------------
def extract_server_info(response):
    headers_lower = response.lower()

    for line in response.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.strip()

    # fallback detection
    if "cloudflare" in headers_lower:
        return "Server: Cloudflare (hidden)"
    if "gws" in headers_lower:
        return "Server: Google Web Server (hidden)"
    if "envoy" in headers_lower:
        return "Server: Envoy Proxy (hidden)"

    return "Server header not found"


# -------------------------------
# Identify Server Type
# -------------------------------
def identify_server(response):
    res = response.lower()

    fingerprints = {
        "apache": "Apache",
        "nginx": "Nginx",
        "microsoft-iis": "Microsoft IIS",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "gws": "Google Web Server",
        "awselb": "AWS Load Balancer",
        "lighttpd": "Lighttpd",
        "envoy": "Envoy Proxy"
    }

    for key, value in fingerprints.items():
        if key in res:
            return value

    return "Unknown"


# -------------------------------
# Scan Single Host (UPDATED)
# -------------------------------
def scan_host(host):

    # -------- HTTP --------
    http_start = time.time()
    http_response = retry(grab_http_banner, host)
    http_end = time.time()
    http_time = round(http_end - http_start, 2)

    http_server = extract_server_info(http_response)
    http_type = identify_server(http_response)

    # -------- HTTPS --------
    https_start = time.time()
    https_response = retry(grab_https_banner, host)
    https_end = time.time()
    https_time = round(https_end - https_start, 2)

    https_server = extract_server_info(https_response)
    https_type = identify_server(https_response)

    # -------- PRINT OUTPUT --------
    with lock:
        print(f"\n--- {host} ---")

        print(f"[HTTP]  {http_server}")
        print(f"[HTTP]  Identified: {http_type}")
        print(f"⏱ HTTP Time:  {http_time} sec")

        print(f"[HTTPS] {https_server}")
        print(f"[HTTPS] Identified: {https_type}")
        print(f"⏱ HTTPS Time: {https_time} sec")

        # Comparison insight (nice for demo)
        diff = round(https_time - http_time, 2)
        print(f"⚡ HTTPS is {diff} sec slower than HTTP")

        # Banner preview
        if isinstance(http_response, str):
            preview = http_response[:200].replace("\r\n", " ")
            print(f"📄 Preview: {preview}")


# -------------------------------
# Main (Multi-threaded)
# -------------------------------
def main():
    user_input = input("Enter websites (comma separated): ").strip()

    if user_input:
        targets = [t.strip() for t in user_input.split(",")]
    else:
        targets = [
            "example.com",
            "google.com",
            "github.com",
            "stackoverflow.com"
        ]

    threads = []
    start = time.time()

    for host in targets:
        t = threading.Thread(target=scan_host, args=(host,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end = time.time()

    print(f"\n🚀 Total Scan Time: {round(end - start, 2)} seconds")

    print("\n📊 Observations:")
    print("- HTTPS is slower due to SSL/TLS handshake")
    print("- Multi-threading reduces total scan time")
    print("- Some servers hide their identity for security")


# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    main()
