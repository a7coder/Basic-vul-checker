import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import concurrent
import csv


def get_all_links(url):
    print("********************* Getting All The Links From the Site *********************")
    print()
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()

    for anchor in soup.find_all('a'):
        href = anchor.get('href')
        if href and not href.startswith('mailto:'):
            absolute_url = urljoin(url, href)
            links.add(absolute_url)
    print("********************* All Links Are Fetched *********************")
    print()
    return links

def check_link_status(link):
    try:
        response = requests.head(link)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

broken_links = []
visited={}
def scan_website(url, max_depth=None, current_depth=0):
    try:
        if max_depth is not None and current_depth > max_depth:
            return set(), 0, []

        all_links = get_all_links(url)
        valid_links = 0
        # print("ALl links",all_links)
        print("************************ Scanning The Website , Please Wait *********************")
        print()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_link_status, link): link for link in all_links}
            
            for future in concurrent.futures.as_completed(futures):
                link = futures[future]
                status_code = future.result()

                if link not in visited:
                    visited[link]=1

                if status_code is not None:
                    valid_links += 1
                    
                    
                else:
                    broken_links.append(link)

        next_depth = current_depth + 1
        for link in all_links:
            if link not in visited:
                _, _, link_broken = scan_website(link, max_depth, next_depth)
                broken_links.extend(link_broken)

        return all_links, valid_links, broken_links
    except:
        print("Something went wrong")
    

def save_results(url, total_links, valid_links, broken_links, save_file):
    try:
        print("********************* Saving The File *********************")
        print()
        with open(save_file+'.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Website URL", "Total Links", "Valid Links", "Broken Links"])
            writer.writerow([url, total_links, valid_links, len(broken_links)])
            writer.writerow([])  # Empty row
            if broken_links:
                writer.writerow(["Broken Link"])

            for link in broken_links:
                writer.writerow([link])
        print("********************* Files has been saved *********************")
        print()
    except:
        print("Something went wrong")

def main():
    try:
        url = input("Enter the website URL: ")
        max_depth = int(input("Enter the maximum depth: "))
        save_file = input("Enter the file name to save results (leave blank for no saving): ")

        all_links, valid_links, broken_links = scan_website(url, max_depth)

        print("Total links checked:", len(all_links))
        print("No. of Valid links:", valid_links)
        print("No. of Broken links:", len(broken_links))
        if broken_links:
            print('********************** List of Broken Links **********************')
        for link in broken_links:
            print("Broken link:", link)

        if save_file:
            save_results(url, len(all_links), valid_links, broken_links, save_file)
    except:
        print("Something went wrong")

if __name__ == "__main__":
    
        main()
    
