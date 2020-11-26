from config import ha_API
import requests
import json
import time

url = "https://itunes.apple.com.register-appleid.services/"
header = {
    'api-key': ha_API,
    'accept': 'application\json',
    'user-agent': 'Falcon Sandbox'
}

# make quick-scan req.
resp = None

try:
    resp = requests.post("https://www.hybrid-analysis.com/api/v2/quick-scan/url",
                         headers=header, verify=False, data={'scan_type': 'all', 'url': url})
    resp.raise_for_status()
except requests.exceptions.HTTPError as e:
    print("Issue with HA request ", e)
    if resp:
        print(resp.text)
    exit()

id = resp.json()['id']
# print(json.dumps(resp.json(), indent = 4))

# time.sleep(5)
delay = 5
# keep checking in until the scan is complete
if not resp.json()['finished']:
    print("Waiting for results please wait a few seconds (retries):", end='')

while not resp.json()['finished']:
    print('|', end='')
    time.sleep(delay)
    delay = 2
    try:
        resp = requests.get(
            "https://www.hybrid-analysis.com/api/v2/quick-scan/"+id, headers=header, verify=False)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print("Issue with Hybrid Analysis request ", e)
        print(resp.text)
        exit()
    # print(json.dumps(resp.json(), indent = 4))

resp_json = resp.json()

reports = resp_json['reports']

for scanner in resp_json['scanners']:
    print("{} : {}".format(scanner['name'], scanner['status']), end='')
    if scanner['name'] == "VirusTotal":
        print("{}%% detection rate".format(scanner['percent']))
    else:
        print()

# get reports
if len(reports):
    for report in reports:
        try:
            resp = requests.get(
                "https://www.hybrid-analysis.com/api/v2/report/{}/summary".format(report), headers=header, verify=False)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Issue with HA request ", e)
            exit()

        ha_verdict = resp.json()['verdict']

        print("Report {} verdict: {}\nsee more at https://www.hybrid-analysis.com/sample/{}/{}".format(
            report, ha_verdict, resp_json['sha256'], report))
else:
    print("No reports for this URL")
# print(json.dumps(resp.json(), indent = 4))
