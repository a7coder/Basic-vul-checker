import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
from scan import get_all_links

def send(resp, data):
    parent_url, form_url = resp['parent_url'], resp['action']
    visited = set()
    visited.add(form_url)
    visited.add(parent_url)
    if resp['method'] == 'post':
        response = requests.post(
            form_url, data=data, allow_redirects=False, timeout=5)
        while response.status_code == 302:
            redirect_url = response.headers['Location']
            if not (redirect_url.startswith("http") or redirect_url.startswith("https")):
                redirect_url = urljoin(parent_url, redirect_url)
            if redirect_url in visited:
                response.status_code = 404
                return response
            response = requests.post(
                redirect_url, data=data, allow_redirects=False, timeout=5)
            visited.add(redirect_url)
    else:
        response = requests.get(form_url, data=data,
                                allow_redirects=False, timeout=5)
        while response.status_code == 302:
            redirect_url = response.headers['Location']
            if not (redirect_url.startswith("http") or redirect_url.startswith("https")):
                redirect_url = urljoin(parent_url, redirect_url)
            if redirect_url in visited:
                response.status_code = 404
                return response
            response = requests.get(
                redirect_url, data=data, allow_redirects=False, timeout=5)
            visited.add(redirect_url)
    return response

def generate_payload():
    ans = ''
    with open('payloads.txt', 'r') as f:
        ans = f.read()
    res = ans.split('\n')
    return res

def check_payload(resp):
    if resp.status_code == 200:
        return True
    return False

def run_link_attack(url):
    try:
        payloads = generate_payload()
        query = urlparse(url).query
        if query != "":
            for payload in payloads:
                query_payload = query.replace(
                    query[query.find("=")+1:len(query)], payload, 1)
                test = url.replace(query, query_payload, 1)
                query_all = url.replace(query, urlencode(
                    {x: payload for x in parse_qs(query)}))
                _respon = requests.get(test, timeout=5)
                if check_payload(_respon) or check_payload(requests.get(query_all, timeout=5)):
                    return {'severity': 'Medium', 'target_url': url, 'vulnerable_url': _respon.url, 'title': 'SQL-INJECTION', 'method': 'GET', 'description': f'SQL-INJECTION vulnerability found at vulnerable url with payload {payload}'}
        else:
            return None
    except Exception as e:
        return None
    
def run_form_attack(resp):
    payloads = generate_payload()
    for payload in payloads:
        keys = {}
        for item in resp['field']:
            keys[item] = payload
        if 'submit' in resp:
            keys[resp['submit'][0]] = resp['submit'][1]
        req = send(resp, keys)
        if check_payload(req):
            return (True, keys)
    return (False, keys)

def run_sql(url):
    try:
        res = requests.get(url, timeout=5)
        bsObj = BeautifulSoup(res.content, "html.parser")
        forms = bsObj.find_all("form", method=True)
        result = []
        for form in forms:
            resp = {}
            try:
                if (form['action'].startswith('https') or form['action'].startswith('http')):
                    resp["action"] = form["action"]
                else:
                    resp["action"] = urljoin(url, form["action"])
            except KeyError:
                resp["action"] = res.url
            if form["method"].lower().strip() == "post":
                resp['method'] = 'post'
            else:
                resp['method'] = 'get'
            for key in form.find_all(["input", "textarea"]):
                try:
                    if key.has_attr('name') and key.name == 'input' and key['type'] == 'submit':

                        resp['submit'] = (key['name'], key['value'])

                    elif key.has_attr('name') and ((key.name == 'textarea') or (key.name == 'input')):

                        if 'field' not in resp:
                            resp['field'] = set()

                        resp['field'].add(key['name'])
                except Exception as e:
                    continue
            try:
                resp['parent_url'] = url
                ans = run_form_attack(resp)
                if ans[0]:
                    result.append({'severity': 'High', 'target_url': url, 'vulnerable_url': resp['action'], 'title': 'SQL-INJECTION', 'method': resp['method'].upper(
                    ), 'description': f"SQL-INJECTION vulnerability found at vulnerable url with payload {ans[1]}"})
            except Exception as e:
                continue
        return result
    except:
        return []


def run_both_attack(url):
    return (run_sql(url), run_link_attack(url))

def sql_injection(url):
    try:
        res = requests.get(url, timeout=5)
        resp = []
        if res.status_code == 200:
            all_links = get_all_links(url)
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(run_both_attack, link)
                           for link in all_links]
                for future in concurrent.futures.as_completed(futures):
                    ans = future.result()
                    if ans and ans[0]:
                        resp.append(ans[0])
                    if len(ans) == 2 and ans[1]:
                        resp.append(ans[1])
            return resp
    except Exception as e:
        return f'Website is Down {e}'

if __name__ == '__main__':
    a = sql_injection('http://testphp.vulnweb.com')
    print('Ans is ',)
    print(a)
    print('Length ', len(a))
