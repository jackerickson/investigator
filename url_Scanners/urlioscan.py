from config import urlscan_API
import json
import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "reddit.com"

urlscan_link = "https://urlscan.io/api/v1/scan/"
headers = {
    "Content-Type": "application/json",
    "API-Key": urlscan_API
}

data = {
    "url": url,
    "visibility": "public"
}

try:
    resp = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data), verify=False)
    resp.raise_for_status()
except requests.exceptions.HTTPError as e:
    print(e)
    exit()

print(json.dumps(resp.json(),  indent = 4))
result = resp.json()['api']
print("result link", result)
time.sleep(10)

resp = requests.get(result, verify=False)

print(json.dumps(resp.json(), indent=4))

while resp.json()['status'] == 404:
    print("checking")

    time.sleep(2)
    resp = requests.get(result, verify=False)
    print(json.dumps(resp.json()['message'], indent=4))




print(resp.json())