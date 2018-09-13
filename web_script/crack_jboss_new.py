# coding=utf-8
# author:wolf
import base64
import re
import urllib.request as ur
import urllib.parse as up

def get_plugin_info():
    plugin_info = {
        "name": "Jboss弱口令",
        "info": "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "http://www.shack2.org/article/156.html",
        "keyword": "tag:jboss",
        "source": 1
    }
    return plugin_info

def check_path(check_url):
    try:
        res = ur.urlopen(check_url, timeout=timeout)
        return 1
    except Exception as e:
        if "401" in str(e) :
            return 1
        else : return 0

def check(url, timeout):
    flag_list = ['>jboss.j2ee</a>','JBoss JMX Management Console','HtmlAdaptor?action=displayMBeans','<title>JBoss Management']
    user_list = ['admin','manager','jboss','root']
    login_url = url + '/jmx-console'
    if check_path(login_url) == 1:
        for user in user_list:
            for password in PASSWORD_DIC:
                request = ur.Request(login_url)
                auth_str_temp = user+':'+password
                auth_str = base64.b64encode(auth_str_temp.encode('utf-8'))
                request.add_header('Authorization', 'Basic ' + str(auth_str,"utf-8"))
                res = ur.urlopen(request,timeout=timeout)
                res_html = res.read()
                for flag in flag_list:
                    if flag in res_html:
                        info = u'[+] %s 存在弱口令，用户名：%s，密码：%s'%(login_url, user,password)
                        return info
    else : pass

    login_url = url + '/console/App.html'
    if check_path(login_url) == 1:
        for user in user_list:
            for password in PASSWORD_DIC:
                request = ur.Request(login_url)
                auth_str_temp = user+':'+password
                auth_str = base64.b64encode(auth_str_temp.encode('utf-8'))
                request.add_header('Authorization', 'Basic ' + str(auth_str,"utf-8"))
                res = ur.urlopen(request,timeout=timeout)
                res_html = res.read()
                for flag in flag_list:
                    if flag in res_html:
                        info = u'[+] %s 存在弱口令，用户名：%s，密码：%s'%(login_url, user,password)
                        return info
    else : pass

    login_url = url + '/admin-console/login.seam'
    if check_path(login_url) == 1:
        for user in user_list:
            for password in PASSWORD_DIC:
                res_html = ur.urlopen(login_url).read()
                if '"http://jboss.org/embjopr/"' in res_html:
                    key_str = re.search('javax.faces.ViewState\" value=\"(.*?)\"',res_html)
                    key_hash = up.quote(key_str.group(1))
                    PostStr = "login_form=login_form&login_form:name=%s&login_form:password=%s&login_form:submit=Login&javax.faces.ViewState=%s"%(user,password,key_hash)
                    request = ur.Request(login_url,PostStr)
                    res = ur.urlopen(request,timeout=timeout)
                    if 'admin-console/secure/summary.seam' in res.read():
                        info = u'[+] %s 存在弱口令，用户名：%s，密码：%s'%(login_url, user,password)
                        return info
    else : return