import socket


def grab_banner(ip, port, sock=None, timeout=1.0):
    """
    Try to read a service banner from an open port.
    Some services (SSH, FTP) send a banner right away.
    Others (HTTP) need a request sent first before they respond.
    Returns the banner as a string, or None if nothing was received.
    """
    own_socket = False
    try:
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            own_socket = True

        sock.settimeout(timeout)

        # HTTP-like ports stay silent until they get a request
        if port in (80, 443, 8080, 8000):
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
            sock.send(request)

        data = sock.recv(1024)
        banner = data.decode(errors="ignore").strip()

        return banner if banner else None

    except Exception:
        return None

    finally:
        if own_socket:
            sock.close()
