import hashlib
import json
import os
import sys
import time
import tkinter as tk
import signal
from tkinter.constants import TRUE
from requests.sessions import Request
import urllib3
from tkinter import filedialog
from xml.etree import ElementTree
from colorama import init, Fore, Back
from config import vt_API, wf_API, ha_API, http

import requests

# import VxAPI-master

# end usage plan (PUBLIC file scan):
#   Enter function:
#   f = upload file, u = submit download url, x = more info on previous scan
# *confidential scan will be seperate if automated at all so as to prevent accidental cross usage


def signal_handler(sig, frame):
    print("Quitting CTL+C interrupt")
    sys.exit(0)


def vt_filescan(subject):
    id = hashlib.sha256(subject.read()).hexdigest()
    negCommunityScore = False
    engine_detections = False

    vt_API_URL = "http://www.virustotal.com/api/v3/files/{}".format(id)
    headers = {'x-apikey': vt_API}
    resp = requests.Response()
    try:
        resp = http.get(vt_API_URL, headers=headers, verify=False)
    except requests.exceptions.HTTPError as e:
        try:
            resp = http.post("https://www.virustotal.com/api/v3/files",
                             headers=headers, files={'file': subject}, verify=False)
            print(resp.text)
            while resp.status_code == 404:
                print("retrying")
                resp = requests.get(vt_API_URL, headers=headers, verify=False)

            print(resp.text)

        except requests.exceptions.HTTPError as e:
            print("Error getting VirusTotal results:", e)
            return

    # print(json.dumps(resp.json(),indent = 4))
    vt_results = resp.json()['data']['attributes']
    vt_scan_link = "https://www.virustotal.com/gui/url/{}".format(id)

    print("VirusTotal results:")
    # check if any engines got a hit on this link and show them
    stats = vt_results['last_analysis_stats']
    engine_results = vt_results['last_analysis_results']
    malicious_detections = stats['malicious']
    suspicious_detections = stats['suspicious']

    # print engines that detected this IP
    if int(stats['malicious']) > 0 or int(stats['suspicious']) > 0:
        print(Fore.RED + "{} Detections".format(malicious_detections +
                                                suspicious_detections))
        for engine in engine_results:
            if engine_results[engine]['result'] not in (None, "clean", "undetected"):
                print("\t{} => {}:{}".format(
                    engine, engine_results[engine]['result'], engine_results[engine]['category']))
    else:
        print(Fore.GREEN + "No detections")

    names = vt_results.get('names')
    if names:
        print("Known filenames for this hash")
        for name in names:
            print("\t{}".format(name))

    vote_results = vt_results['reputation']
    if vote_results > 0:
        print(Fore.GREEN + "VT community score {}".format(vote_results))
    elif vote_results < 0:
        print(Fore.RED + "VT community score {}".format(vote_results))
    else:
        print("VT community score: {}".format(vote_results))

    # https cert info
    print("See full scan results at {}".format(vt_scan_link))
    subject.seek(0)


def vt_file_upload_scan(size, subject):

    vt_BASE_URL = "http://www.virustotal.com/api/v3/"
    vt_url_files = "files/"
    headers = {'x-apikey': vt_API}

    if size > 32e6:
        print("big file")
        try:
            resp = http.get(
                "http://www.virustotal.com/api/v3/files/upload_url", headers=headers)
        except requests.exceptions.HTTPError as e:
            print("Error getting upload url:", e)
        vt_upload_url = resp.json()['data']
    else:
        vt_upload_url = "http://www.virustotal.com/api/v3/files"

    files = {'file': subject}
    try:
        resp = requests.post(vt_upload_url, headers=headers, files=files)
    except requests.exceptions.HTTPError as e:
        print("Server error. File might be too large and blocked by the firewall.\n", e)
        return

    print(json.dumps(resp.json(), indent=4))
    analysis_id = resp.json()['data']['id']
    try:
        resp = http.get(
            vt_BASE_URL+"analyses/{}".format(analysis_id), headers=headers)
    except requests.exceptions.HTTPError as e:
        print("Error getting analysis: ", e)

    # print(json.dumps(resp.json(), indent=4))
    backoff = 0
    if resp.json()['data']['attributes']['status'] == "queued" or resp.json()['data']['attributes']['status'] == "in-progress":
        print("Waiting for response: ", end='')
    while resp.json()['data']['attributes']['status'] == "queued" or resp.json()['data']['attributes']['status'] == "in-progress":
        time.sleep(2**backoff)
        print("|", end='')
        if backoff < 4:
            backoff += 1
        # print(json.dumps(resp.json(), indent=4))

        # print("in queue, waiting {} seconds to retry".format(2**backoff))
        resp = requests.get(
            vt_BASE_URL+"analyses/{}".format(analysis_id), headers=headers)
    # print(json.dumps(resp.json(), indent=4))
    print("VirusTotal results:")

    vt_results = resp.json()['data']['attributes']
    # vt_scan_link = "https://www.virustotal.com/gui/url/{}".format(url_id)

    print("VirusTotal results:")
    # check if any engines got a hit on this link and show them
    stats = vt_results['last_analysis_stats']
    engine_results = vt_results['last_analysis_results']
    malicious_detections = stats['malicious']
    suspicious_detections = stats['suspicious']

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
    #
    # print(json.dumps(resp.json()['data']['attributes']['stats'], indent=4))
    subject.seek(0)


def ha_filescan(filename, subject):

    # HA_BASEURL = "https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1602689449862"
    HA_BASEURL = "https://www.hybrid-analysis.com/api/v2/"

    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': ha_API
    }
    files = {
        'scan_type': (None, 'all'),
        'file': (filename, subject),
    }

    # with open(file_path, 'rb') as subject:

    # try:
    #     resp = requests.post(HA_BASEURL+"search/hash", verify=False, headers=headers,
    #                          data={'hash': hashlib.sha256(subject.read()).hexdigest()})
    #     print(json.dumps(resp.json(), indent=4))

    #     if resp.json()[0]['state'] == 'SUCCESS':
    #         print(
    #             "This file hasn't been seen before, uploading it to Hybrid Analysis")
    #         data = {'file': subject,
    #                 'environment_id': '120'
    #                 }

    #         resp = requests.post(HA_BASEURL + "submit/file",
    #                              verify=False, headers=headers, data=data)
    #         print(json.dumps(resp.json(), indent=4))

    # except requests.exceptions.HTTPError as e:
    #     print("Error submitting file hash for search in Hybrid Analysis: " + e)
    resp = None
    try:
        resp = http.post(HA_BASEURL + "quick-scan/file",
                         headers=headers, files=files, verify=False, timeout=(10, 10))
    except requests.exceptions.HTTPError as e:
        print("Error uploading to HA: ", e)
        return

    except requests.exceptions.HTTPError as e:
        print("Issue with HA request ", e)
        if resp:
            print(resp.text)
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
                "https://www.hybrid-analysis.com/api/v2/quick-scan/"+id, headers=headers, verify=False)
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

    # first check hash
    subject.seek(0)


def wf_filescan(subject, filename):
    file_obj = (filename, subject)

    body_hash = {
        'apikey': (None, wf_API),
        'hash': (None, hashlib.sha256(subject.read()).hexdigest())
    }
    try:
        resp = http.post(
            "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash, verify=False)

        tree = ElementTree.fromstring(resp.content)
        # print(resp.text)
        verdict = int(tree[0].find('verdict').text)
    except requests.exceptions.HTTPError as e:
        print("Error making wildfire request attempting upload: ", e)
        verdict = -102

    if verdict == -102:
        body_file = {
            'apikey': (None, wf_API),
            'file': (filename, subject)
        }
        print("This file doesn't exist in WildFire, uploading now. Please wait a few seconds for the verdict.")
        try:
            resp = requests.post(
                "https://wildfire.paloaltonetworks.com/publicapi/submit/file", files=body_file, verify=False)
        except requests.exceptions.HTTPError as e:
            print("Error uploading the file to Wildfire: ", e)
            print(resp.text)
            return
        try:
            resp = ElementTree.fromstring(http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash), verify=False.content)

        except requests.exceptions.HTTPError as e:
            pass
            #print("Error getting verdict from uploaded file: ", e)
        except requests.exceptions.ConnectTimeout as e:
            print("Timed out uploading the file to wildfire: "), e
            return
        bckoff = 1
        while verdict == -100 or verdict == -102:
            print("Waiting for verdict")
            time.sleep(2**bckoff)
            bckoff += 1

            resp = ElementTree.fromstring(http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash).content)
            verdict = int(resp[0][1].text)
        # tree = ElementTree.fromstring(resp.content)
    elif verdict == -101:
        print("error")

    print("WF verdict: ", end=' ')
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
    subject.seek(0)


def get_filepath():

    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename()





def single_file_info(file_path):

    banner_size = os.get_terminal_size()[0]
    filename = file_path.split('/')[-1]
    size = os.stat(file_path).st_size
    try:
        with open(file_path, 'rb') as subject:
            print(banner_size*'/', end='')
            print(banner_size*'‾', end='')
            print(Back.BLUE + "File INFO FOR {}".format(filename))
            print(banner_size*'_', end='')
            try:
                vt_filescan(subject)
            except Exception as e:
                print("General Error getting Virus Total results ", e.with_traceback)

            print(banner_size*'_', end='')
            try:
                ha_filescan(filename, subject)
            except Exception as e:
                print("General Error getting Virus Total results ", e.with_traceback)
            print(banner_size*'_', end='')
            try:
                wf_filescan(subject, filename)
            except Exception as e:
                print("General Error getting Virus Total results ", e.with_traceback)
            print(banner_size*'_', end='')

            print(banner_size*'/', end='')
    except OSError as e:
        print("Couldn't open the file: ", e)

    return


def file_info():
    print("File scanner tool: Scan file on VirusTotal, and Wildfire\nUsage: press enter to select a file.")
    while(1):
        search = None
        while search == None:
            search = input("File Scan (b to go back)\n=>")
        if search == 'b':
            return
        else:
            file_path = get_filepath()
            if not file_path or file_path == '':
                print("No file selected")
            else:
                single_file_info(file_path)


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
    run = True
    while run:
        try:
            file_info()
            run = False
        except Exception as e:
            print("General error ", e.with_traceback)
