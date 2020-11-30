from ipaddress import IPv4Address
import ip_search
import url_search
import urllib3
import sys
import signal
import os
import json
import config
from colorama import init
# from config import configure, wf_API, vt_API


def signal_handler(sig, frame):
    sys.exit(0)


def main():

    # config.configure()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    signal.signal(signal.SIGINT, signal_handler)

    # init colorama
    init(autoreset=True)

    BASE_PATH = os.path.dirname(os.path.realpath(__file__))
    # with open('config.json', 'rb') as f:
    #     configuration = json.load(f)

    # config.vt_API = configuration['vt_api_key']
    # # ha_API = config['ha_api_key']
    # config.wf_API = configuration['wf_api_key']

    print("Investigator\nUsage: Enter one or more IP addresses or URLs to get information. To force an IP or a URL lookup enter the sub investigation menu by entering 'i' or 'u'")
    try:
        while (1):
            selection = input(
                "Input or Select an investigation option. (i = ip, u = url) \n=> ")
            if selection == 'i':
                ip_search.ip_info()
            elif selection == 'u':
                url_search.url_info()
            else:
                if len(selection) != 0:
                    for item in selection.split(" "):
                        if len(item) != 0:
                            try:
                                IPv4Address(item)
                                ip_search.single_ip_info(item)
                            except:
                                url_search.single_url_info(item)
    except Exception as e:
        print("Woops... General error:", e)


if __name__ == "__main__":
    main()
