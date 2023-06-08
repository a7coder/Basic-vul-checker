
import requests
from collections import deque
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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


parent_dict = {}
def get_all_links(url):
    
    print("********************* Getting All The Links From the Site *********************")
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

    print('URL is ',url,requests.head(https_url).status_code)

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
    print(all_links,len(all_links))
    return all_links
   
    
# get_all_links('ptu.ac.in')
print(get_domain('https://music.app.youtube.com'))
# print(parent_dict)

