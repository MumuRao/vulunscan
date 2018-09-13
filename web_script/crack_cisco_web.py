#coding=utf-8
import urllib.request as ur
import urllib.error as ue
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
        "name": "Cisco_WEB弱口令",
        "info": "攻击者可进入web控制台，进而接管控制设备。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:cisco",
        "source": 1
    }
    return plugin_info

def check(url,timeout):
    error_i = 0
    user_list=['admin','cisco','root']
    try:
        ur.urlopen(url, timeout=timeout)
        return
    except ur.HTTPError as e:
        if e.code != 401:return
    except:
        return
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                request = ur.Request(url)
                auth_str_temp = user+':'+pass_
                auth_str = base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic '+auth_str)
                res = ur.urlopen(request,timeout=timeout)
                res_code = res.code
                if res_code == 200:
                    return u'[+] %s 存在弱口令 %s:%s' % (url, user, pass_)
            except ue.HTTPError:
                continue
            except ue.URLError as e:
                error_i+=1
                if error_i >= 3:return
                continue
            else:
                pass