from random import randint
import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin,parse_qs,urlencode
from bs4 import BeautifulSoup
from scan import get_all_links


def generate_payload():
    ans=''
    with open('scripts/payloads.txt','r') as f:
        ans=f.read()
    res=ans.split('\n')
    return res

def check_payload(resp):
    # print('Status Code ',resp.status_code)
    if resp.status_code ==200:
        return True
    return False


def run_link_attack(url):
    try:
        print('Link Attack ****************',url)
        payloads=generate_payload()
        query=urlparse(url).query

        if query != "":
            for payload in payloads:

                payload = generate_payload()
                
                
                query_payload=query.replace(query[query.find("=")+1:len(query)],payload,1)
                test=url.replace(query,query_payload,1)

                query_all=url.replace(query,urlencode({x:payload for x in parse_qs(query)}))

                _respon=requests.get(test)

                if check_payload(_respon) or check_payload(requests.get(query_all)):
                        
                    return {'severity':'Medium','target_url':url,'vulnerable_url':_respon.url,'title':'SQL-INJECTION','method':'GET','description':f'SQL-INJECTION vulnerability found at vulnerable url with payload {payload}'}
        else:
            return None
    except:
        return None


def run_form_attack(resp):
    print('Form Attack ****************',resp)
    payloads=generate_payload()
    for payload in payloads:

        keys = {}
        
        for item in resp['field']:
            keys[item] = payload

        # print('Payloads are ******************')
        if 'submit' in resp:
            keys[resp['submit']]=resp['submit']
        if resp['method'] == 'post':
            # print('Post*********')
            req = requests.post(resp['action'], data=keys)
        
        else:
          
            req = requests.get(resp['action'], params=keys)
    
        if check_payload(req):
            # print('Content ********************* are ',req.text)
            # print('Payload is ',payload)
            return (True,keys)

    return (False,keys)


def run_sql(url):
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
                    if key.name == 'input'  and key['type']=='submit' and key.has_attr('name'):
                        
                        resp['submit']=key['name']

                    elif (key.name == 'textarea') or (key.name == 'input' and key.has_attr('name')):
                        
                        if 'field' not in resp:
                            resp['field'] = set()
                        
                        resp['field'].add(key['name'])
                    

                except Exception as e:
                    print('Excepiton',e,key)
                    print(key.has_attr('name'))
                    continue

            try:
                # print('******Respponse is ',resp)
                ans =run_form_attack(resp)
                # print('Ans is ',ans)
                if ans[0]:

                    result.append({'severity':'High','target_url':url,'vulnerable_url':resp['action'],'title':'SQL-INJECTION','method':resp['method'].upper(),'description':f"SQL-INJECTION vulnerability found at vulnerable url with payload {ans[1]}"})
            except:
                continue
        
        return result
    except :
        return []
    
def run_both_attack(url):
    
    return (run_sql(url),run_link_attack(url))


def sql_injection(url):

    try:
        
        res = requests.get(url, timeout=5)
        
        resp=[]
        if res.status_code == 200:
            all_links=get_all_links(url)
            print('All links fetched****************')
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

    print(sql_injection('http://testphp.vulnweb.com/login.php'))