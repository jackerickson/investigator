from tkinter.constants import TRUE
from xml.etree.ElementTree import ElementTree
import requests
import json
from requests.api import head
import urllib3
import signal
import time
import sys
import base64
import os
from xml.etree import ElementTree
from colorama import init, Fore, Back
from config import vt_API, wf_API, ha_API,  http


def signal_handler(sig, frame):
    print("Quitting CTL+C interrupt")
    sys.exit(0)


def wf_url_scan(url):

    body = {
        'apikey': (None, wf_API),
        'url': (None, url)
    }
    try:
        resp = http.post(
            "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body)

    except requests.exceptions.HTTPError as e:
        print("Error getting Palo Alto Wildfire results: ", e)
        return
    try:
        # parser = ElementTree.XMLParser()
        # tree = ElementTree.fromstring(resp.content, parser=parser)
        tree = ElementTree.fromstring(resp.content)
        # verdict = int(tree[0][1].text)
        verdict = int(tree[0].find('verdict').text)
        # valid = str(tree[0][3].text)
        valid = str(tree[0].find('valid').text)
    except Exception as e:
        print("Please remove all '/' from your input to get wildfire verdict. current parser breaks", e)
        # print(resp.text)
        return

    if valid == 'Yes':
        print("Wildfire Verdict: ", end=' ')
    else:
        print("Invalid URL for Wildfire")
    if verdict == -102:
        body = {
            'apikey': (None, wf_API),
            'link': (None, url)
        }
        print("sample not in Wildfire database, submitting for analysis")
        try:
            resp = http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/submit/link", files=body)

        except requests.HTTPError as e:
            print("Error submitting file to Wildfire: ", e)
            return
        time.sleep(2)
        body = {
            'apikey': (None, wf_API),
            'url': (None, url)
        }
        try:
            resp = http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body)
        except requests.HTTPError as e:
            print("Error getting Palo Alto Wildfire results: ", e)
            return
        tree = ElementTree.fromstring(resp.content)
        verdict = int(tree[0][1].text)

    retry = 0

    while verdict == -100 or verdict == -102:
        if retry > 4:
            print(
                "File is taking a while to analyze on WildFire. Search again in a few minutes.")
            return
        retry += 1
        print("pending")
        time.sleep(2)
        body = {
            'apikey': (None, wf_API),
            'url': (None, url)
        }
        resp = http.post(
            "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body)
        tree = ElementTree.fromstring(resp.content)
        verdict = int(tree[0][1].text)

    if verdict == 0:
        print(Fore.GREEN + "benign")
    elif verdict == 1:
        print(Fore.RED + "malware")
    elif verdict == 2:
        print(Fore.RED + "grayware")
    elif verdict == 4:
        print(Fore.RED + "phishing")
    elif verdict == 5:
        print(Fore.RED + "C2")
    elif verdict == -101:
        print(Fore.RED + "wildfire unspecified error")
    elif verdict == -103:
        print(Fore.RED + "invalid hash value")


def vt_url_scan(url):
    negCommunityScore = False
    engine_detections = False
    url_id = url_id = base64.urlsafe_b64encode(
        url.encode()).decode().strip("=")
    vt_API_URL = "http://www.virustotal.com/api/v3/urls/{}".format(url_id)
    headers = {'x-apikey': vt_API}
    resp = requests.Response()
    try:
        resp = http.get(vt_API_URL, headers=headers, verify=False)

    except requests.exceptions.HTTPError as e:
        try:
            resp = http.post("https://www.virustotal.com/api/v3/urls",
                             headers=headers, files={'url': url}, verify=False)
            print(resp.text)
            resp = http.get(vt_API_URL, headers=headers, verify=False)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                print("The supplied URL is invalid")
            else:
                print("Error getting VirusTotal results:", e)
            return

    # print(json.dumps(resp.json(),indent = 4))
    vt_results = resp.json()['data']['attributes']
    vt_scan_link = "https://www.virustotal.com/gui/url/{}".format(url_id)

    print("VirusTotal results:")
    # check if any engines got a hit on this link and show them
    stats = vt_results['last_analysis_stats']
    engine_results = vt_results['last_analysis_results']
    malicious_detections = stats['malicious']
    suspicious_detections = stats['suspicious']
    # for stat in stats:
    #     if (stat == "malicious" or stat == "suspicious"):
    #         if int(stats[stat]) > 0:
    #             engine_detections = True
    #             print(Fore.RED + "{} : {}".format(stat, stats[stat]))
    #         else:
    #             print(Fore.GREEN + "{} : {}".format(stat, stats[stat]))
    # else:
    #         print("{} : {}".format(stat, stats[stat]))

    # print engines that detected this IP
    if int(stats['malicious']) > 0 or int(stats['suspicious']) > 0:
        print(Fore.RED + "{} Detections".format(malicious_detections +
                                                suspicious_detections))
        for engine in engine_results:
            if engine_results[engine]['result'] not in (None, "clean", "unrated"):
                print("\t{} => {}:{}".format(
                    engine, engine_results[engine]['result'], engine_results[engine]['category']))
    else:
        print(Fore.GREEN + "No detections")

    vote_results = vt_results['reputation']
    if vote_results > 0:
        print(Fore.GREEN + "VT community score {}".format(vote_results))
    elif vote_results < 0:
        print(Fore.RED + "VT community score {}".format(vote_results))
    else:
        print("VT community score: {}".format(vote_results))

    # https cert info
    print("See full scan results at {}".format(vt_scan_link))

    return vt_results.get("last_final_url")


def ha_url_scan(url):
    # url = "https://itunes.apple.com.register-appleid.services/"

    print("Hybrid analysis and other scanners\n")

    header = {
        'api-key': ha_API,
        'accept': 'application\json',
        'user-agent': 'Falcon Sandbox'
    }

    resp = None
    # make quick-scan req.

    try:
        resp = http.post("https://www.hybrid-analysis.com/api/v2/quick-scan/url",
                         headers=header, verify=False, data={'scan_type': 'all', 'url': url})
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            print("The supplied URL is invalid")
        else:
            print("Issue with HA request (", e + ')')
        # if resp:
        #     print(resp.text)
        return

    id = resp.json()['id']
    # print(json.dumps(resp.json(), indent = 4))

    # time.sleep(5)
    delay = 10
    # keep checking in until the scan is complete
    if not resp.json()['finished']:
        print("Waiting for Hybrid Analysis, please wait (retries):", end='')

    while not resp.json()['finished']:
        print('|', end='')
        time.sleep(delay)
        delay = 2
        try:
            resp = http.get(
                "https://www.hybrid-analysis.com/api/v2/quick-scan/"+id, headers=header, verify=False)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Issue with Hybrid Analysis request ", e)
            print(resp.text)
            return
        if resp.json()['finished']:
            print()
        # print(json.dumps(resp.json(), indent = 4))

    resp_json = resp.json()

    reports = resp_json['reports']

    for scanner in resp_json['scanners']:
        if scanner['name'] != "VirusTotal":
            print("{} : {} ".format(
                scanner['name'], scanner['status']))

    # get reports
    if len(reports):
        for i, report in enumerate(reports):
            try:
                resp = http.get(
                    "https://www.hybrid-analysis.com/api/v2/report/{}/summary".format(report), headers=header, verify=False)
                resp.raise_for_status()
                ha_verdict = resp.json()['verdict']

                print("Hybrid Analysis report {} verdict: {}\nsee more at https://www.hybrid-analysis.com/sample/{}/{}".format(
                    i+1, ha_verdict, resp_json['sha256'], report))
            except requests.exceptions.HTTPError as e:
                pass

    else:
        print("No reports for this URL")
    # print(json.dumps(resp.json(), indent = 4))


# def urlscanio_scan(url):
#     urlscan_link = "https://urlscan.io/api/v1/scan/"
#     headers = {
#         "Content-Type": "application/json",
#         "API-Key": urlscan_API
#     }

#     data = {
#         "url": url,
#         "visibility": "public"
#     }

#     try:
#         resp = requests.post("https://urlscan.io/api/v1/scan/",
#                              headers=headers, data=json.dumps(data), verify=False)
#         resp.raise_for_status()
#     except requests.exceptions.HTTPError as e:
#         print(e)
#         return
#     result = "https://urlscan.io/api/v1/scan/" + resp.json()['uuid']

#     time.sleep(10)

#     resp = requests.get(result, verify=False)
#     print(json.dumps(resp.json(), indent=4))

#     while resp.json()['status'] == 404:
#         time.sleep(2)
#         resp = requests.get(result, verify=False)
#         print("checking")

#     print(resp.json())


def single_url_info(url):
    if not url or url == '':
        print("Blank URL")
        return

    banner_size = os.get_terminal_size()[0]
    print(banner_size*'/', end='')
    print(banner_size*'‾', end='')
    print(Back.BLUE + "URL INFO FOR {}".format(url))
    print(banner_size*'_', end='')
    final_url = vt_url_scan(url)
    print(banner_size*'_', end='')
    ha_url_scan(url)
    print(banner_size*'_', end='')
    wf_url_scan(url)
    print(banner_size*'_', end='')
    # urlscanio_scan(url)
    # print(banner_size*'_', end='')
    print(banner_size*'/', end='')
    if final_url and final_url != url:
        print(Fore.BLUE + "This URL redirects to another URL, checking that too")
        single_url_info(final_url)


def url_info():
    print("URL scanner tool: Search URL on VirusTotal, and Wildfire\nUsage: enter one or more URLs seperate by spaces.")
    while(1):
        search = None
        while search == None:
            search = input("URL Search (b to go back)\n=>")
        if search == 'b':
            return
        banner_size = os.get_terminal_size()[0]
        for url in search.split(' '):
            single_url_info(url)


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    init(autoreset=True)
    # import API keys from config file
    BASE_PATH = os.path.dirname(os.path.realpath(__file__))

    os.path.exists('config.json')
    # with open('config.json', 'rb') as f:
    #         configuration = json.load(f)
    # vt_API = configuration['vt_api_key']
    # wf_API = configuration['wf_api_key']

    signal.signal(signal.SIGINT, signal_handler)
    url_info()