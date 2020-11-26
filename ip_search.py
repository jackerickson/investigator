import sys
import requests
import json
import signal
import os
import urllib3
from colorama import Fore, Back, init
import ipaddress
from datetime import datetime


from config import vt_API, wf_API, http


def signal_handler(sig, frame):
    print("Quitting CTL+C interrupt")
    sys.exit(0)


def get_ip_info(ip):
    try:
        res = http.get("http://ip-api.com/json/" + ip)
    except requests.exceptions.HTTPError as e:
        print("Error getting ip whois:", e)
        return
    except requests.exceptions.ConnectTimeout as e:
        print("Connection to ip-api.com timed out")
        return
    ipInfo = res.json()
    if ipInfo['status'] == 'success':
        print(("Country: {}\n"
               "Region: {}\n"
               "Region Name: {}\n"
               "City: {}\n"
               "Post code: {}\n"
               "IP Range owner: {}\n"
               "IP Assignee: {}"
               ).format(ipInfo['country'], ipInfo['region'], ipInfo['regionName'], ipInfo['city'], ipInfo['zip'], ipInfo['isp'], ipInfo['org']))
    else:
        print("Whois lookup did not return a result for this address.")
    return


def vt_ip(ip):
    engine_detections = False

    # print(vt_API)
    vt_API_URL = "http://www.virustotal.com/api/v3/ip_addresses/{}".format(ip)
    headers = {'x-apikey': vt_API}
    try:
        resp = requests.get(vt_API_URL, headers=headers, verify=False)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print("Error getting VirusTotal results:", e)
        return

    vt_results = resp.json()['data']['attributes']

    print("VirusTotal results:")
    # check if any engines got a hit on this link and show them
    stats = vt_results['last_analysis_stats']
    engine_results = vt_results['last_analysis_results']

    for stat in stats:
        if (stat == "malicious" or stat == "suspicious"):
            if int(stats[stat]) > 0:
                engine_detections = True
                print(Fore.RED + "{} : {}".format(stat, stats[stat]))
            # else:
            #         print(Fore.GREEN + "{} : {}".format(stat, stats[stat]))

    if not engine_detections:
        print(Fore.GREEN + "No detections for this IP")

    # print engines that detected this IP
    if int(stats['malicious']) > 0 or int(stats['suspicious']) > 0:
        print("This IP was detected by the following engines")
        for engine in engine_results:
            if engine_results[engine]['result'] not in (None, "clean", "undetected", "unrated"):
                print("\t{} => {}:{}".format(
                    engine, engine_results[engine]['result'], engine_results[engine]['category']))

    vote_results = vt_results['reputation']
    if vote_results > 0:
        print(Fore.GREEN + "VT community score {}".format(vote_results))
    elif vote_results < 0:
        print(Fore.RED + "VT community score {}".format(vote_results))
    else:
        print("VT community score: {}".format(vote_results))

    # https cert info
    resolutions = {}

    try:
        resp = http.get(vt_API_URL + "/resolutions", headers=headers)
        resolutions = resp.json()['data']
    except requests.exceptions.HTTPError as e:
        print("Couldn't get name resolution info: ", e)
    except requests.exceptions.ConnectTimeout as e:
        print("Timeout getting DNS connections")

    if len(resolutions) > 0:
        print("\nLast 3 DNS resolutions for this IP (Y-M-D)")
        for index, name in zip(range(3), resolutions):
            print("{} : {}".format(datetime.utcfromtimestamp(resolutions[index]['attributes']['date']).strftime(
                '%Y-%m-%d'), resolutions[index]['attributes']['host_name']))

    vt_scan_link = "https://www.virustotal.com/gui/ip-address/{}".format(ip)
    print("See full scan results at {}".format(vt_scan_link))


def single_ip_info(ip):

    banner_size = os.get_terminal_size()[0]
    print(banner_size*'/', end='')
    print(banner_size*'‾', end='')
    print(Back.BLUE + "IP INFO FOR {}".format(ip))
    print(banner_size*'_', end='')
    get_ip_info(ip)
    print(banner_size*'_', end='')
    vt_ip(ip)
    print(banner_size*'_', end='')
    print(banner_size*'/', end='')


def ip_info():
    print("IP scanner tool: Whois, VirusTotal scan, and reverse DNS lookup\nUsage: enter one or more IPs seperate by spaces.")
    while(True):
        search_ips = ""
        while not search_ips:
            search_ips = input("IP Lookup (b to go back)\n=> ")
        if search_ips == 'b':
            return
        # just some funky formatting. Not required.
        banner_size = os.get_terminal_size()[0]
        for ip in search_ips.split():
            try:
                ipaddress.IPv4Address(ip)

                print(banner_size*'/', end='')
                print(banner_size*'‾', end='')
                print(Back.BLUE + "IP INFO FOR {}".format(ip))
                print(banner_size*'_', end='')
                get_ip_info(ip)
                print(banner_size*'_', end='')
                vt_ip(ip)
                print(banner_size*'_', end='')
                print(banner_size*'/', end='')
            except ValueError as e:
                print("Woops {} isn't a valid ipv4 address\n".format(ip))


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # register the exit handler
    signal.signal(signal.SIGINT, signal_handler)

    # import API keys from config file
    # BASE_PATH = os.path.dirname(os.path.realpath(__file__))

    init(autoreset=True)

#     os.path.exists('config.json')
#     with open('config.json', 'rb') as f:
#         configuration = json.load(f)
#     vt_API = configuration['vt_api_key']

    # implement direct usage
    if len(sys.argv) > 1:
        for ip in sys.argv[1:]:
            get_ip_info(ip)
            vt_ip(ip)
        sys.exit(0)

    print("""Usage: Use this tool to search for information on one or more ips\n
                To search multiple IPs split each ip address with a space\n
                Example inputs: '192.168.0.1' or '8.8.8.8 10.0.0.1'\n
                ips can be passed as arguments to the script as well\n
                Example: py ip_search.py\n""")

    ip_info()
    sys.exit(0)
