import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
    'Content-Type': 'application/x-stapler-method-invocation;charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Crumb': "5277b0d3-6d2a-4790-b2f0-680017c9d462",
    }

cookies = {
    "JSESSIONID.913cd934": "node01s46xrper5pwj1u959a44kmeb5217.node0",
    "screenResolution": "1366x768",
    }

url = "http://10.1.16.200:8080/$stapler/bound/129bea04-d3df-478d-8073-9af7e7242060/start"
res = requests.post(url, headers = headers, cookies = cookies, data = "[]")
print (res)
