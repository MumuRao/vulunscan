# coding=utf-8
import urllib.request as ur
import ssl
import base64

try:
    _create_unverified_https_context = ssl._create_unverified_context  # 忽略证书错误
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


def get_plugin_info():
    plugin_info = {
        "name": "锐捷AC弱口令",
        "info": "攻击者可进入web控制台，进而接管控制设备。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "banner:RGOS;port:80",
        "source": 1
    }
    return plugin_info

def check_path(check_url):
    try:
        res = ur.urlopen(check_url, timeout=timeout)
        return 1
    except Exception as e:
        if "405" in str(e) :
            return 1
        else : return 0

def check(url, timeout):
    user_list = ['admin']
    login_url = url + "/login.do"
    if check_path(login_url) == 1:
        for user in user_list:
            for pass_ in PASSWORD_DIC:
                pass_ = str(pass_.replace('{user}', user))
                request = ur.Request(url)
                auth_str_temp = user + ':' + pass_
                auth_str = base64.b64encode(auth_str_temp)
                postdata = "auth=" + auth_str
                res = ur.urlopen(request, postdata, timeout=timeout)
                res_html = res.read()
                if "Success" in res_html:
                    return u'[+] %s 存在弱口令 %s:%s' % (login_url, user, pass_)
    else : return
