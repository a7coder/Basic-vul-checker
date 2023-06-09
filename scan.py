import datetime
import requests
import socket
import time
import ssl
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from cipher import weak_cipher_suites
start_time = time.time()

def main(url, resp=[]):
    check_ssl(url, resp)
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            host_domain_name = get_host__domain(url)
            broken_links(url, host_domain_name,resp)
            check_security_headers(url, resp)
            check_open_ports(url, resp)
    except:
        resp.append({"severity":"Critical","target_url": url,"title":"Website Down", "method":"GET", "vulnerable_url": url, "description": f"Host URL {url} is down"})
    elapsed_time = time.time() - start_time
    print(resp)
    print(elapsed_time)

def get_host__domain(url):
    Domain_name = ''
    x = url.split("/")
    
    if(x[0] == "https:" or x[0] == "http:"):
        x = x[2].split(".")
    else:
        x = x[0].split(".")
    if(len(x) == 2):
        Domain_name = x[0]
    else:
        Domain_name = x[1]
    return Domain_name

def broken_links(url, host_domain_name,resp):
    crawled_urls = set()
    queue = []
    queue.append(url)
    while queue:
        link = queue.pop()
        try:
            response = requests.get(link, timeout=5)
            if not response.status_code == 200:
                resp.append({"severity":"Info","target_url": url,"title":"Broken Links", "method":"GET", "vulnerable_url": link, "description": "Invalid URL with status code {}".format(response.status_code)})
            crawled_urls.add(link)
        except:
            resp.append({"severity":"Info","target_url": url,"title":"Broken Links", "method":"GET", "vulnerable_url": link, "description": "Invalid URL"})
            continue
        soup = BeautifulSoup(response.text, 'html.parser')
        for anchor in soup.find_all("a"):
            try:
                link = anchor.attrs["href"]
            except:
                continue
            if link and not (link.startswith("mailto:") or link.startswith("javascript:") or link.startswith('tel') or link.startswith('#')):
                if link.startswith("/"):
                    base_url = urlparse(url).scheme + "://" + urlparse(url).netloc
                    link = base_url + link
                elif not link.startswith("http"):
                    link = urljoin(url, link)
                link_domain = get_host__domain(link)
                if not link in queue and not link in crawled_urls and link_domain == host_domain_name:
                    queue.append(link)
    return 0

def check_security_headers(url, resp):
    response = requests.get(url)
    headers = response.headers
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
    ]
    for header in security_headers:
        if not header in headers:
            resp.append({'severity':'Low','target_url':url,'vulnerable_url':'','title':'Security headers','method':'GET','description':'{} is not present.'.format(header)})

def check_open_port(host, port, resp):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = 'Unknown'
            s.close()
            if port != 80 and port != 443:
                return (port, service)
            elif port == 443:
                resp.append({'severity':'Info','target_url':host,'vulnerable_url':host,'title':'Open Ports','method':'GET','description':'Port 443 is open and service running on it is : HTTPS'})
                check_ssl(host, resp)
            elif port == 80:
                resp.append({'severity':'Medium','target_url':host,'vulnerable_url':host,'title':'Open Ports','method':'GET','description':'Port 80 is open and service running on it is : HTTP'})
        s.close()

def check_open_ports(url, resp):
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    ip = socket.gethostbyname(host)
    with ThreadPoolExecutor(max_workers=500) as executor:
        tasks = [executor.submit(check_open_port, host, port, resp)
                 for port in range(1, 65535)]
        for future in concurrent.futures.as_completed(tasks):
            result = future.result()
            if result:
                resp.append({'severity':'Low','target_url':url,'vulnerable_url':ip,'title':'Open Ports','method':'GET','description':'Port {} is open and service running on it is : {}'.format(result[0], result[1])})

def check_ssl(host, resp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    ssl_sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    try:
        ssl_sock.connect_ex((host, 443))
        cert = ssl_sock.getpeercert()
        expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        current_date = datetime.datetime.now()
        days_to_expiry = (expiry_date - current_date).days
        ssl_version = ssl_sock.version()
        cipher_suite = ssl_sock.cipher()
        
        if days_to_expiry < 30:
            resp.append({'severity':'High','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL Certificate is going to expire in {} days.'.format(days_to_expiry)})
        elif days_to_expiry < 90:
            resp.append({'severity':'Low','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL Certificate is going to expire in {} days.'.format(days_to_expiry)})
        else:
            resp.append({'severity':'Info','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL Certificate is going to expire in {} days.'.format(days_to_expiry)})
        
        if ssl_version.startswith(('TLSv1.3')) or ssl_version.startswith(('TLSv1.2')):
            pass
        else:
            resp.append({'severity':'High','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL/TLS version is outdated & current version is {}'.format(ssl_version)})

        if cipher_suite in weak_cipher_suites:
            resp.append({'severity':'High','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL/TLS is using weak cipher suite: {} & may be vulnerable.'.format(cipher_suite)})
    except ssl.SSLError as e:
        resp.append({'severity':'Medium','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'SSL Error: {}'.format(str(e))})
    except socket.error as e:
        resp.append({'severity':'Medium','target_url':host,'vulnerable_url':host,'title':'SSL/TLS','method':'GET','description':'Socket Error: {}'.format(str(e))})
    finally:
        ssl_sock.close()
        sock.close()

main("http://www.deadlinkcity.com/")