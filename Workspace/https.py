import socket
import ssl
from urllib.parse import urlparse

def CheckSSLCertificate(url):
    context = ssl.create_default_context()
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or 443 
        if not host:
            raise ValueError("Invalid URL. Please provide a valid URL with a hostname.")
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return True

    except ssl.SSLError as e:
        return False
    except socket.timeout:
        return False
    except (socket.gaierror, ConnectionError) as e:
        return False
    except ValueError as e:
        return False

url = "https://google.com"
print(CheckSSLCertificate(url))