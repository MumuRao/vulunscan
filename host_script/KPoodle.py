#coding:utf-8
import ssl,socket,sys

def get_plugin_info():
    plugin_info = {
        "name": "SSLv3 Poodle攻击漏洞",
        "info": "CVE-2014-3566 该漏洞贯穿于所有的SSLv3版本中，利用该漏洞，黑客可以通过中间人攻击等类似的方式(只要劫持到的数据加密两端均使用SSL3.0)，便可以成功获取到传输数据",
        "level": "高危",
        "type": "中间人劫持",
        "author": "郭驰",
        "url": "http://www.freebuf.com/news/47172.html",
        "keyword": "tag:ssl",
        "source": 1
    }
    return plugin_info

SSL_VERSION={
    'SSLv2':ssl.PROTOCOL_SSLv2,
    'SSLv3':ssl.PROTOCOL_SSLv3,
    'SSLv23':ssl.PROTOCOL_SSLv23,
    'TLSv1':ssl.PROTOCOL_TLSv1,
}

def check_ssl_version(version, ip, port):
    try:
        https = ssl.SSLSocket(socket.socket(),ssl_version=SSL_VERSION.get(version))
        c = https.connect((ip,int(port)))
        #print version + ' Supported'
        return True
    except Exception as e:
        return False
#USAGE = '==========\nKPoodle – SSL version and poodle attack vulnerability detect tool\n==========\nUsage: python kpoodle.py target port(default:443)\n\nby kingx'

def check(ip, port, timeout):
    try:
        #print 'Connecting…'
        s = socket.socket().connect((ip,int(port)))
    except Exception as e:
        #print e
        #print 'Can not connect to the target!'
        return '目标无法连接'
        sys.exit()

    try:
        #print 'Checking…'
        ssl3 = check_ssl_version('SSLv3', ip, int(port))
        ssl2 = check_ssl_version('SSLv2', ip, int(port))
        ssl23 = check_ssl_version('SSLv23', ip, int(port))
        tls = check_ssl_version('TLSv1', ip, int(port))
        if ssl3:
            #print '\nSSLv3 Poodle Vulnerable!'
            return u'存在SSLv3 Poodle漏洞'
        #else:
            #print '\nNo SSLv3 Support!'
            #return u'\n未发现SSLv3 Poodle漏洞'
    except Exception as e:
        #print e
        return e