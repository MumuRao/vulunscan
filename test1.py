import urllib.request as ur
import http.cookiejar as hc
import re
import json

def set_request(request,crumb,url):
    request.add_header('Content-Type', 'application/x-stapler-method-invocation;charset=UTF-8')
    request.add_header('X-Requested-With', 'XMLHttpRequest')
    request.add_header('Referer', url + '/asynchPeople/')
    request.add_header('Crumb', crumb)

def test():
    user_list = []
    url = "http://10.1.16.200:8080"
    timeout = 10
    cj = hc.CookieJar()
    opener = ur.build_opener(ur.HTTPCookieProcessor(cj))
    req = opener.open(url + "/asynchPeople/")
    res_html = req.read().decode("utf-8")
    m = re.search("makeStaplerProxy\('(.*?)','(.*?)'",res_html)
    if m:
        user_url = url + m.group(1)
        crumb = m.group(2)
        request = ur.Request(user_url+"/start","[]".encode(encoding='UTF8'))
        set_request(request,crumb,url)
        opener.open(request, timeout=timeout)
        # try:
            # opener.open(request, timeout=timeout)
        # except Exception as e:
            # print (e)
        while True:
            request = ur.Request(user_url+"/news","[]".encode())
            set_request(request,crumb, url)
            user_data = opener.open(request, timeout=timeout).read()
            print (user_data)
            if len(user_data) >=20:
                user_array = json.loads(user_data)
                for _ in user_array["data"]:
                    user_list.append(_["id"].encode("utf-8"))
                if user_array["status"] == "done":break
            else:break
    print (user_list)
    #except Exception as e:
        # if "401" in str(e) or "302" in str(e) or "301" in str(e):
            # return "1234"
        # else :
            # return e
    # return "123"
       # print (e)

test()
