import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from collections import deque

def scan_broken_links(url):
    try:
        resp=[]
        all_links = get_all_links(url)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_link_status, link, resp): link for link in all_links}
            concurrent.futures.wait(futures)
        return resp
    except:
        return "Something went wrong"

parent_dict = {}
def get_all_links(url):

    actual_domain = get_host__domain(url)
    all_links = set()
    queue_links = deque([])
    visited = set()

    all_links.add(url)
    queue_links.append(url)

    while queue_links:
        url = queue_links.popleft()
        if url.endswith('/'):
            url = url[:-1]
        if url not in visited and get_host__domain(url) == actual_domain:
            response = requests.get(url,timeout=5)
            if not response.status_code == 200:
                all_links.add(url)
                visited.add(url)
                continue
            soup = BeautifulSoup(response.text, 'html.parser')
            for anchor in soup.find_all('a'):
                href = anchor.get('href')
                if href and not (href.startswith("mailto:") or href.startswith("javascript:") or href.startswith('tel') or href.startswith('/#') or href.startswith('#')):
                    absolute_url = href
                    if not (absolute_url.startswith("http") or absolute_url.startswith("https")):
                        absolute_url = urljoin(url, href)
                    if absolute_url.endswith('/'):
                        absolute_url = absolute_url[:-1]
                    if absolute_url not in parent_dict:
                        parent_dict[absolute_url] = set()
                    parent_dict[absolute_url].add(url)
                    all_links.add(absolute_url)
                    queue_links.append(absolute_url)
        visited.add(url)
    return all_links

def check_link_status(link, resp):
    try:
        response = requests.get(link, timeout=2)
        if response.status_code != 200:
            resp.append({"severity": "Info", "target_url": parent_dict[link], "title": "Broken Links", "method": "GET",
                        "vulnerable_url": link, "description": "Invalid URL with status code {}".format(response.status_code)})
            return False
        return True
    except:
        resp.append({"severity": "Info", "target_url": parent_dict[link], "title": "Broken Links",
                    "method": "GET", "vulnerable_url": link, "description": "Invalid URL"})
        return False

def get_host__domain(url):
    Domain_name = ''
    x = url.split("/")
    if (x[0] == "https:" or x[0] == "http:"):
        x = x[2].split(".")
    else:
        x = x[0].split(".")
    if (len(x) == 2):
        Domain_name = x[0]
    else:
        Domain_name = x[1]
    return Domain_name

def check_security_headers(url):
    try:
        resp=[]
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
                resp.append({'severity': 'Low', 'target_url': url, 'vulnerable_url': '', 'title': 'Security headers',
                            'method': 'GET', 'description': '{} is not present.'.format(header)})
        return resp
    except:
        return 'Website is Down'