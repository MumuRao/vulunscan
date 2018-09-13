#-*- encoding:utf-8 -*-
import urllib.request as ur 

def get_plugin_info():
    plugin_info = {
        "name": "grafana 弱口令",
        "info": "对grafana控制台进行弱口令检测",
        "level": "高危",
        "type": "弱口令",
        "author": "hos@YSRC",
        "url": "https://hackerone.com/reports/174883",
        "keyword": "banner:grafana",
        "source": 1
    }
    return plugin_info

def check_path(check_url):
    try:
        res = ur.urlopen(check_url, timeout=timeout)
        return 1
    except Exception as e:
        if "401" in str(e) or "405" in str(e) :
            return 1
        else : return 0

def check(url, timeout):
    url += "/login"
    header={
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36',
    'ContentType': 'application/x-www-form-urlencoded; chartset=UTF-8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.8',
    'Connection': 'close'
    }
    if check_path(url) == 1:
        for password in PASSWORD_DIC:
            data = {"user":"admin","email":"","password":password}
            data = up.urlencode(data).encode("UTF-8")
            request = ur.Request(url = url,data = data,headers = header)
            res = ur.urlopen(request,timeout=timeout)
            if "Logged in" in res.read():
                info = u'[+] %s 存在弱口令，用户名：%s，密码：%s' % (url, "admin", password)
                return info
    else : return
