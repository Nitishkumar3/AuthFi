import socket
import ssl
from urllib.parse import urlparse
import requests
import dns.resolver

def CheckSiteUp(url):
    try:
        response = requests.head(url, timeout=5)
        return 200 <= response.status_code < 400
    except requests.ConnectionError:
        return False
    
def FormatURL(url):
    if url.startswith("https://"):
        url = url.rstrip('/').lower()  
        return url
    elif url.startswith("http://"):
        url = "https://" + url[7:].rstrip('/').lower()  
        return url
    else:
        url = "https://" + url.rstrip('/').lower() 
        return url
    
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
    
def CheckTXTRecord(Domain, SiteID):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        Domain = Domain.replace("https://", "")
        answers = resolver.resolve(Domain, 'TXT')
        txtrecords = [txtrecord.decode('utf-8') for rdata in answers for txtrecord in rdata.strings]
        if SiteID in txtrecords:
            return True
        else:
            return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception as e:
        return False