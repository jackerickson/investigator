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
from lxml import etree
from colorama import init, Fore, Back
from config import vt_API, wf_API, ha_API, http

import requests

# signal handler for running file search by itself


def signal_handler(sig, frame):
    print("Quitting CTL+C interrupt")
    sys.exit(0)

# run a virus total scan by searching for the hash of the file in VT
# input: subject: file bytes


def vt_filescan(subject):
    # get hash and build request link/headers
    id = hashlib.sha256(subject.read()).hexdigest()

    vt_API_URL = "http://www.virustotal.com/api/v3/files/{}".format(id)
    headers = {'x-apikey': vt_API}
    resp = requests.Response()
    try:
        resp = http.get(vt_API_URL, headers=headers, verify=False)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print("Hash not in Virus Total")
        else:
            print("error checking with Virus Total: ", e)
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

    # if we got any malicious or suspicious detectons print engines that detected this IP
    if int(stats['malicious']) > 0 or int(stats['suspicious']) > 0:
        print(Fore.RED + "{} Detections".format(malicious_detections +
                                                suspicious_detections))
        # print each of the engine's results
        for engine in engine_results:
            if engine_results[engine]['result'] not in (None, "clean", "undetected"):
                print("\t{} => {}:{}".format(
                    engine, engine_results[engine]['result'], engine_results[engine]['category']))
    else:
        print(Fore.GREEN + "No detections")

    # Check for known file names in Virus Total
    names = vt_results.get('names')
    if names:
        print("Known filenames for this hash")
        for name in names:
            print("\t{}".format(name))

    # print the reputation of the file
    vote_results = vt_results['reputation']
    if vote_results > 0:
        print(Fore.GREEN + "VT community score {}".format(vote_results))
    elif vote_results < 0:
        print(Fore.YELLOW + "VT community score {}".format(vote_results))
    else:
        print("VT community score: {}".format(vote_results))

    print("See full scan results at {}".format(vt_scan_link))

# run a HybridAnalysis filescan, this scan I actually upload the file, if > 100MB the upload will fail


def ha_filescan(filename, subject):

    HA_BASEURL = "https://www.hybrid-analysis.com/api/v2/"
    header = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': ha_API
    }
    files = {
        'scan_type': (None, 'all'),
        'file': (filename, subject),
    }
    # upload the file
    resp = None
    try:
        print("Uploading file to Hybrid Analysis")
        resp = http.post(HA_BASEURL + "quick-scan/file",
                         headers=header, files=files, verify=False, timeout=60)
    except requests.exceptions.Timeout as e:
        print("Error uploading to Hybrid Analysis: connection timed out")
        return

    except requests.exceptions.HTTPError as e:
        try:
            resp = http.post(
                "https://www.hybrid-analysis.com/api/v2/search/hash", headers=header, data={'hash': hashlib.sha256(subject.read()).hexdigest()}, verify=False)
            print("Couldn't upload the file (might be too large) checking hash instead")

        except Exception as e:
            print("Issue with HA request", e)
            return

    id = resp.json()['id']

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
                "https://www.hybrid-analysis.com/api/v2/quick-scan/"+id, header=header, verify=False)
        except requests.exceptions.HTTPError as e:

            print("Issue with Hybrid Analysis request ", e)
            print(resp.text)
            return
        if resp.json()['finished']:
            print()

    # now go thorugh each of the scanners in the repsonse and print their results

    resp_json = resp.json()

    for scanner in resp_json['scanners']:
        if scanner['name'] != "VirusTotal":
            print(scanner['name'])
            if scanner['status'] == 'clean':
                print(Fore.GREEN + "\t{} ".format(
                    scanner['status']))
            elif scanner['status'] == 'malicious':
                print(Fore.RED + "\t{} ".format(
                    scanner['status']))
            else:
                print(Fore.YELLOW + "\t{} ".format(
                    scanner['status']))

    # Get any hybrid analysis reports for this and display their verdict along with a link to them
    reports = resp_json.get('reports')

    if len(reports):
        for i, report in enumerate(reports):
            try:
                resp = http.get(
                    "https://www.hybrid-analysis.com/api/v2/report/{}/summary".format(report), headers=header, verify=False)

                ha_verdict = resp.json()['verdict']

                if ha_verdict == 'no specific threat':
                    print("Hybrid Analysis report {} verdict: {}{}".format(
                        i+1, Fore.GREEN, ha_verdict))
                    print("see more at https: // www.hybrid-analysis.com/sample/{}/{}".format(
                        resp_json['sha256'], report))
                elif ha_verdict == 'malicious':
                    print("Hybrid Analysis report {} verdict: {}{}".format(
                        i+1, Fore.RED, ha_verdict))
                    print("see more at https: // www.hybrid-analysis.com/sample/{}/{}".format(
                        resp_json['sha256'], report))
                else:
                    print("Hybrid Analysis report {} verdict: {}{}".format(
                        i+1, Fore.YELLOW, ha_verdict))
                    print("see more at https: // www.hybrid-analysis.com/sample/{}/{}".format(
                        resp_json['sha256'], report))

            except requests.exceptions.HTTPError as e:
                pass

    else:
        print("No reports for this URL")
    # first check hash


def wf_filescan(filename, subject):
    file_obj = (filename, subject)

    body_hash = {
        'apikey': (None, wf_API),
        'hash': (None, hashlib.sha256(subject.read()).hexdigest())
    }
    try:
        resp = http.post(
            "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash, verify=False)

        tree = etree.fromstring(resp.content)
        # print(resp.text)
        verdict = int(tree[0].find('verdict').text)
    except requests.exceptions.HTTPError as e:
        print("Error searching in wildfire, attempting upload: ", e)
        verdict = -102

    if verdict == -102:
        body_file = {
            'apikey': (None, wf_API),
            'file': (filename, subject)
        }
        print("This file doesn't exist in WildFire, uploading now. Please wait a few seconds for the verdict.")
        # upload the file
        try:
            resp = etree.fromstring(requests.post(
                "https://wildfire.paloaltonetworks.com/publicapi/submit/file", files=body_file, verify=False).content)
            print("Wildfire upload response\n", resp)
            if resp.tag == 'error':
                print("Wildfire file upload failed")
                return

        except requests.exceptions.HTTPError as e:
            print("Error uploading the file to Wildfire: ", e)
            return
        # wait a bit try and read the verdict
        time.sleep(5)
        try:
            resp = etree.fromstring(http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash, verify=False).content)

        except requests.exceptions.HTTPError as e:
            pass
            # print("Error getting verdict from uploaded file: ", e)
        except requests.exceptions.ConnectTimeout as e:
            print("Timed out uploading the file to wildfire: "), e
            return
        # keep trying to get the verdict, using backoff so as not to spam the server
        bckoff = 1
        while verdict == -100 or verdict == -102:
            print("Waiting for verdict")
            time.sleep(2**bckoff)
            bckoff += 1
            resp = etree.fromstring(http.post(
                "https://wildfire.paloaltonetworks.com/publicapi/get/verdict", files=body_hash, verify=False).content)
            verdict = int(resp[0][1].text)
    elif verdict == -101:
        print("Wildfire intenal error")
    print(resp)
    # Get output, these are the result codes wildfire supplies.
    print("WildFire verdict: \n\t", end=' ')
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
        print(Fore.YELLOW + "Wildfire unspecified error")
    elif verdict == -103:
        print(Fore.YELLOW + "Invalid hash (something is wrong this shouldn't happen)")


# utility function to allow the user to select a file from the windows file explorer
def get_filepath():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename()

# search for a single file only using wildfire for confidential files


def single_confidential_file_info(file_path):
    banner_size = os.get_terminal_size()[0]
    filename = file_path.split('/')[-1]
    size = os.stat(file_path).st_size
    try:
        with open(file_path, 'rb') as subject:
            print(banner_size*'/', end='')
            print(banner_size*'‾', end='')
            print(Back.BLUE + "(confidential) File INFO FOR {}".format(filename))
            print(banner_size*'_', end='')
            try:
                wf_filescan(filename, subject)
            except Exception as e:
                print("General Error getting Wildfire results ", e)
            subject.seek(0)
            print(banner_size*'_', end='')

            print(banner_size*'/', end='')
    except OSError as e:
        print("Couldn't open the file: ", e)
    return

# search for a file using all methods


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
                print("General Error getting Virus Total results ", e)
            subject.seek(0)
            print(banner_size*'_', end='')
            try:
                ha_filescan(filename, subject)
            except Exception as e:
                print("General Error getting Hybrid Analysis results ", e)
            subject.seek(0)
            print(banner_size*'_', end='')
            try:
                wf_filescan(filename, subject)
            except Exception as e:
                print("General Error getting Wildfire results ", e)
            subject.seek(0)
            print(banner_size*'_', end='')

            print(banner_size*'/', end='')
    except OSError as e:
        print("Couldn't open the file: ", e)

    return

# this is the menu loop. we stay here until the user wants to go back to the general search.


def file_info():
    print(("File scanner tool: Scan file on VirusTotal, and Wildfire\n"
           "Please note the tools general limit file uploads to 100MB\n"
           "Usage: press enter to select a file, use command 'x' to scan a confidential file"))
    while(1):
        try:
            # get command input and check what to do with it
            search = None
            while search == None:
                search = input("File Scan (b to go back)\n=>")
            lower_search = search.lower()
            if lower_search == 'b':
                return
            elif lower_search == 'c':
                if os.name == 'nt':
                    os.system('cls')
                else:
                    os.system('clear')
            elif lower_search == 'x':
                file_path = get_filepath()
                if not file_path or file_path == '':
                    print("No file selected")
                else:
                    single_confidential_file_info(file_path)
            elif lower_search == 'q':
                exit(0)
            else:
                file_path = get_filepath()
                if not file_path or file_path == '':
                    print("No file selected")
                else:
                    single_file_info(file_path)
        except Exception as e:
            print("General error ", e)


# setup for running the file_search in standalone mode.
if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    init(autoreset=True)
    # import API keys from config file
    BASE_PATH = os.path.dirname(os.path.realpath(__file__))

    os.path.exists('config.json')

    signal.signal(signal.SIGINT, signal_handler)
    run = True
    while run:
        try:
            file_info()
            run = False
        except Exception as e:
            print("General error ", e)
