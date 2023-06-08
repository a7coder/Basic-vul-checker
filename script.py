import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import concurrent
import csv
import socket
import ssl

from collections import deque


def get_domain(url):
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


def check_port(port, url):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set the timeout to 1 second
    result = sock.connect_ex((url, port))
    if result == 0:
        service_name = socket.getservbyport(port)
        return (port, service_name)
    sock.close()


def check_open_ports(url: str):
    print("************************ Scanning The Open Ports in the Website, Please Wait *********************")
    print()
    open_ports = []

    
    if url.startswith("http://"):
        url = url[len("http://"):]
    elif url.startswith("https://"):
        url = url[len("https://"):]

    if url.endswith('/'):
        url = url[:-1]

    
    with ThreadPoolExecutor(max_workers=50) as executor:
        
        tasks = [executor.submit(check_port, port, url)
                 for port in range(1, 65535)]

      
        for future in concurrent.futures.as_completed(tasks):
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports


def check_ssl_upgrade(url: str,open_port_list:list):

    if (443, 'https') in open_port_list:
        print("************************ Checking the TLS Certificate, Please Wait *********************")
        print()

        if url.startswith("http://"):
            url = url[len("http://"):]
        elif url.startswith("https://"):
            url = url[len("https://"):]

        if url.endswith('/'):
            url = url[:-1]

        context =  context = ssl.create_default_context()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        sslSocket = context.wrap_socket(s, server_hostname = url)
        sslSocket.connect((url, 443))
        tls_version=sslSocket.version()
    
        
        sslSocket.close()
        if 'TLSv1.3' == tls_version:
            print("************************ No Need to Upgrade TLS Certificate *********************")
            
        else:
            print("************************ Please Upgrade TLS Certificate *********************")
           
    else:
        print("************************ Port 443 is not Open *********************")

    print()
    print(f'************************ Your Current TLS Version is {tls_version} *********************')
        


def check_security_headers(url):
    print("************************ Scanning The Security Headers in the Website, Please Wait *********************")
    print()
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

    present_headers = []

    for header in security_headers:
        if header in headers:
            present_headers.append(header)

    return present_headers

parent_dict = {}
def get_all_links(url):
    
    print("********************* Getting All The Links From the Site *********************")
    print()

    actual_domain=get_domain(url)
    all_links = set()
    queue_links=deque([])

    queue_links.append(url)
    all_links.add(url)

    headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36'}
    response = requests.get(url, headers=headers)

    soup = BeautifulSoup(response.text, 'html.parser')

    for anchor in soup.find_all('a'):

        href = anchor.get('href')

        if href and not (href.startswith("mailto:") or href.startswith("javascript:") or href.startswith('tel') or href.startswith('#')):

            absolute_url = href

            if not (absolute_url.startswith("http") or absolute_url.startswith("https")) :

                absolute_url =urljoin(url, href)
                    

            if  absolute_url not in all_links:

                if url not in parent_dict:
                    parent_dict[url] = set()

                parent_dict[url].add(absolute_url)

                all_links.add(absolute_url)
                queue_links.append(absolute_url)

    while queue_links:

        url= queue_links.popleft()
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        for anchor in soup.find_all('a'):

            href = anchor.get('href')

            if href and not (href.startswith("mailto:") or href.startswith("javascript:") or href.startswith('tel') or href.startswith('#')):

                absolute_url = href

                if not (absolute_url.startswith("http") or absolute_url.startswith("https")) :

                    absolute_url =urljoin(url, href)
                    

                if  get_domain(absolute_url)== actual_domain and absolute_url not in all_links:

                    if url not in parent_dict:
                        parent_dict[url] = set()

                    parent_dict[url].add(absolute_url)
                    all_links.add(absolute_url)
                    queue_links.append(absolute_url)
        

    print("********************** All Links Are Fetched **********************")
    print(all_links)
    return all_links
   

def check_link_status(link):
    try:
        response = requests.head(link)
        return response.status_code
    except requests.exceptions.RequestException:
        return None



def scan_website(url):
    try:    

        all_links = get_all_links(url)
        broken_links = []
        valid_links = 0


        print("************************ Scanning The Website, Please Wait *********************")
        print()
        with ThreadPoolExecutor(max_workers=50) as executor:

            futures = {executor.submit(check_link_status, link): link for link in all_links}

            for future in concurrent.futures.as_completed(futures):
                link = futures[future]
                status_code = future.result()

                if status_code is not None:
                    valid_links += 1

                else:
                    broken_links.append(link)

        
        return all_links, valid_links, broken_links
    
    except:
        print("Something went wrong")


def save_results(url, total_links, valid_links, broken_links, open_ports_list, security_headers_list, save_file):
    try:
        print()
        print("********************* Saving The File *********************")
        print()
        with open(save_file+'.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Website URL", "Total Links",
                            "Valid Links", "Broken Links"])
            writer.writerow([url, total_links, valid_links, len(broken_links)])
            writer.writerow([])  # Empty row

            file.write("Open Ports")
            writer.writerow([])  # Empty row

            for port in open_ports_list:
                file.write(str(port)+'\n')

            writer.writerow([])  # Empty row

            file.write("Security Headers Present")
            writer.writerow([])  # Empty row

            for header in security_headers_list:
                file.write(str(header)+'\n')

            writer.writerow([])  # Empty row
            if broken_links:
                writer.writerow(["Broken Link", 'Found At'])

            for link in broken_links:
                writer.writerow([link, parent_dict[link]])

        print("********************* Files has been saved *********************")
        print()
    except:
        print("Something went wrong")


def main():
    try:
        print()
        url = input("Enter the website URL: ")
        print()
  
        save_file = input(
            "Enter the file name to save results (leave blank for no saving): ")
        print()

        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url

        https_url = url.replace('http://', 'https://', 1)

        if requests.head(https_url).status_code == 200:
                
                url = https_url

        elif 'www' not in https_url:
                    
            https_url =https_url.replace('://', '://www.', 1)

            if requests.head(https_url).status_code == 200:
                
                    url = https_url

        print ('Checking the URL .... ', url)
        print()
        all_links, valid_links, broken_links = scan_website(url)
        open_ports_list = check_open_ports(url)
        security_headers_list = check_security_headers(url)

        print("Total links checked:", len(all_links))
        print()
        print("No. of Valid links:", valid_links)
        print()
        print("No. of Broken links:", len(broken_links))
        print()
        print("Open Ports in The Website are: ", open_ports_list)
        print()
        print('Security Headers Present in the website are: ',
              security_headers_list)
        print()
        
        check_ssl_upgrade(url,open_ports_list)          

        if broken_links:
            print('********************** List of Broken Links **********************')

        for link in broken_links:
            print("Broken link: ", link, ' Found At: ', parent_dict[link])

        if save_file:
            save_results(url, len(all_links), valid_links,
                         broken_links, open_ports_list, security_headers_list, save_file)
            
        

        print()
        print("********************** Script Completed **********************")
        print()
    except Exception as e:
        print("Something went wrong ",e)


if __name__ == "__main__":

    main()
