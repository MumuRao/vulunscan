# coding=utf-8
# author:wolf
import urllib.request as ur

def get_plugin_info():
    plugin_info = {
        "name": "Resin控制台弱口令",
        "info": "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "http://www.360doc.com/content/15/0722/22/11644963_486744404.shtml",
        "keyword": "tag:resin",
        "source": 1
    }
    return plugin_info

def check_path(check_url):
    try:
        res = ur.urlopen(check_url, timeout=timeout)
        return 1
    except Exception as e:
        if "405" in str(e) or "408" in str(e):
            return 1
        else : return 0

def check(url, timeout):
    login_url = url + '/resin-admin/j_security_check?j_uri=index.php'
    if check_path(login_url) == 1:
        flag_list = ['<th>Resin home:</th>', 'The Resin version', 'Resin Summary']
        user_list = ['admin']
        opener = ur.build_opener(ur.HTTPCookieProcessor())
        for user in user_list:
            for password in PASSWORD_DIC:
                PostStr = 'j_username=%s&j_password=%s' % (user, password)
                res = opener.open(login_url, PostStr ,timeout=timeout)
                res_html = res.read()
                res_code = res.code
                for flag in flag_list:
                    if flag in res_html or int(res_code) == 408:
                        info = u'%s/resin-admin 存在弱口令 用户名：%s，密码：%s' % (url, user, password)
                        return info
    else : return