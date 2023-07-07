from random import randint
import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin,parse_qs,urlencode
from bs4 import BeautifulSoup
from scan import get_all_links
import os
import time
def generate_script():
    FUNCTION = [
        "prompt(5000/200)",
        "alert(6000/3000)",
        "alert(document.cookie)",
        "prompt(document.cookie)",
        "console.log(5000/3000)"
    ]
    return "<script>"+FUNCTION[randint(0, 4)]+"</script>"

def run_Quick_link_attack(url):
    try:
        query=urlparse(url).query
        payload = generate_script()
        if query != "":
            query_payload=query.replace(query[query.find("=")+1:len(query)],payload,1)
            test=url.replace(query,query_payload,1)
            query_all=url.replace(query,urlencode({x:payload for x in parse_qs(query)}))
            _respon=requests.get(test)
            if payload in _respon.text or payload in requests.get(query_all).text: 
                return {'severity':'Medium','target_url':url,'vulnerable_url':_respon.url,'title':'XSS','method':'GET','description':f'XSS vulnerability found at vulnerable url with payload {payload}'}
    except:
        return None

def run_Quick_form_attack(resp):
    keys = {}
    payload=generate_script()
    for item in resp['field']:
        keys[item] = payload
    if 'submit' in resp:
        keys[resp['submit'][0]]=resp['submit'][1]
    if resp['method'] == 'post':
        req = requests.post(resp['action'], data=keys,timeout=10)
    else:
        req = requests.get(resp['action'], params=keys,timeout=10)
    if payload in req.text:
        return (True,keys)
    return (False,keys)

def generate_payload():
    li=[]
    for file_name in os.listdir('./xss_payloads'):
        ans = ''
        with open('./xss_payloads/'+file_name, 'r') as f:
            ans = f.read()
        res = ans.split('\n')[:-1]
        li.append(res[randint(0, len(res)-1)])
    return li

def run_link_attack(url,full_scan):
    try:
        if full_scan== False:
            return run_Quick_link_attack(url)
        payloads = generate_payload()
        query = urlparse(url).query
        if query != "":
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = []
                for payload in payloads:
                    query_payload = query.replace(
                        query[query.find("=") + 1:len(query)], payload, 1)
                    test = url.replace(query, query_payload, 1)
                    query_all = url.replace(query, urlencode(
                        {x: payload for x in parse_qs(query)}))
                    futures.append(executor.submit(requests.get, test, timeout=10))
                    futures.append(executor.submit(requests.get, query_all, timeout=10))
                for future, payload in zip(concurrent.futures.as_completed(futures), payloads):
                    try:
                        _respon = future.result()
                        if payload in _respon.text:
                            return {'severity': 'Medium', 'target_url': url, 'vulnerable_url': _respon.url,
                                    'title': 'XSS', 'method': 'GET',
                                    'description': f'XSS vulnerability found at vulnerable url with payload {payload}'}
                    except Exception as e:
                        continue

            return None
    except Exception as e:
        return None
    
def run_form_attack(resp,full_scan):
    if full_scan ==False:
        return run_Quick_form_attack(resp)
    payloads = generate_payload()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for payload in payloads:
            keys = {}
            for item in resp['field']:
                keys[item] = payload
            if 'submit' in resp:
                keys[resp['submit'][0]] = resp['submit'][1]
            if resp['method'] == 'post':
                futures.append(executor.submit(requests.post, resp['action'], data=keys, timeout=10))
            else:
                futures.append(executor.submit(requests.get, resp['action'], params=keys, timeout=10))

        for future, payload in zip(concurrent.futures.as_completed(futures), payloads):
            try:
                req = future.result()
                if payload in req.text:
                    return (True, keys)
            except Exception as e:
                continue
    return (False, keys)

def run_xss(url,full_scan):
    try:
        res = requests.get(url,timeout=10)
        bsObj = BeautifulSoup(res.content, "html.parser",from_encoding="iso-8859-1")
        forms = bsObj.find_all("form", method=True)        
        result=[]
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
                    if key.has_attr('name') and key.name == 'input'  and key['type']=='submit':
                        resp['submit']=(key['name'],key['value'])
                    elif key.has_attr('name') and ((key.name == 'textarea') or (key.name == 'input')):
                        if 'field' not in resp:
                            resp['field'] = set()
                        resp['field'].add(key['name'])
                except Exception as e:
                    continue
            try:
                ans =run_form_attack(resp,full_scan)
                if ans[0]:
                    result.append({'severity':'High','target_url':url,'vulnerable_url':resp['action'],'title':'XSS','method':resp['method'].upper(),'description':f'XSS vulnerability found at vulnerable url with payload {ans[1]}'})
            except:
                continue
        return result
    except :
        return []
    
def run_both_attack(url,full_scan):
    return (run_xss(url,full_scan),run_link_attack(url,full_scan))

def xss(url,full_scan):
    try:
        res = requests.get(url, timeout=10)
        resp=[]
        if res.status_code == 200:
            all_links=get_all_links(url)
            set_max_worker = 50
            if  full_scan:
                set_max_worker=12
            with ThreadPoolExecutor(max_workers=set_max_worker) as executor:
                futures = [executor.submit(run_both_attack, link,full_scan) for link in all_links]            
                for future in concurrent.futures.as_completed(futures):                    
                    ans = future.result()
                    if ans and ans[0]:
                        resp.append(ans[0])
                    if len(ans)==2 and ans[1]:
                        resp.append(ans[1])    
            return resp
    except Exception as e :
        return f'Website is Down {e}'

if __name__ == '__main__':
    t=time.time()
    a=xss('http://testphp.vulnweb.com',True)
    print('Ans is ',)
    print(a)
    print('Length ',len(a))
    print('Time is ', time.time()-t)