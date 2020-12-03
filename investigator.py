from ipaddress import IPv4Address
import ip_search
import url_search
import file_search
import urllib3
import sys
import signal
import os
import json
import config
from colorama import init
# from config import configure, wf_API, vt_API

# setup ctl+c to restart the application from scratch


def signal_handler(sig, frame):
    main()


def main():

    # disable https warnings to prevent scaring users, due to internal self signed certs need to disable ssl verification
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # register signal handler for ctl+c
    signal.signal(signal.SIGINT, signal_handler)

    # init colorama (used for text colouring)
    init(autoreset=True)

    BASE_PATH = os.path.dirname(os.path.realpath(__file__))
    # main program loop. Here is where we make the selection for everything
    while (1):
        try:
            selection = input(
                "Input or Select an investigation option. (enter h for help) \n=> ")

            lower_selection = selection.lower()
            if lower_selection == 'u':
                url_search.url_info()
            elif lower_selection == 'q':
                exit(0)
            elif lower_selection == 'f':
                file_search.file_info()
            elif lower_selection == 'c':
                if os.name == 'nt':
                    os.system('cls')
                else:
                    os.system('clear')
                print("Investigator\nUsage: Enter one or more IP addresses or URLs to get information. Submit 'f' for file search or 'h' for additional info")
            elif lower_selection == 'h':
                print("""How to use the investigator:

Commands (from anywhere):
    q - quit
    c - clear
    b - back
menu navigation commands (from home menu only)
    u - forced URL submission menu
    f - file search

The application will, by default, parse your inputs and determine if it is an IP or a URL.
If you would like to force a url search you can enter the url only search by submtting 'u'
    Example submissions:
        => 8.8.8.8 google.ca
        => 8.8.8.8 8.8.4.4
        => google.ca amazon.ca
        => u
from any menu press b to go back home

File search can be done by entering the file search menu by submitting 'f'.
In this menu you can either just press enter to select a file or submit 'x' to submit a confidential file which will only be checked against Palo Alto Wildfire

All verdict outputs are colour coded based on determined severity. Green = clean result, red = maliciou result. If an output is Yellow, please double check the message to ensure the verdict is safe.

If you would like to interrupt a search, press CTL+C from anywhere to return to the main menu.
                """)
            # not a command so we split input by spaces for multi search, then we check if it's an IP, if not then search as a url
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
            print("Woops... General uncaught error:", e)


if __name__ == "__main__":
    print("Investigator\nUsage: Enter one or more IP addresses or URLs to get information. Submit 'f' for file search or 'h' for additional info")

    main()
