
import os
import json

from requests.api import head
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import requests
# this file is for configuring API keys and the request structure. it provides these for import from the other modules

wf_API = None
vt_API = None
ha_API = None
DEFAULT_TIMEOUT = 10
default_vt_API = 'default API key'
default_wf_API = 'default Wildire key'
default_ha_API = 'default hybrid analysis key'

# setup API keys, try and get them from config.json, use defaults if we can't find the json
BASE_PATH = os.path.dirname(os.path.realpath(__file__))


try:
    with open('config.json', 'rb') as f:
        configuration = json.load(f)
    vt_API = configuration.get('vt_api_key')
    wf_API = configuration.get('wf_api_key')
    ha_API = configuration.get('ha_api_key')

    print("Keys: ", end='')

    print("VirusTotal: ", end='')
    if not vt_API:
        print("default", end='')
        vt_API = default_vt_API
    else:
        print("user", end='')
    print("\t Hybrid Analysis: ", end='')
    if not wf_API:
        print("default", end='')
        wf_API = default_wf_API
    else:
        print("user", end='')
    print("\t Wildfire: ", end='')
    if not ha_API:
        print("default", end='')
        ha_API = default_ha_API
    else:
        print("user", end='')
    print()


except FileNotFoundError:
    print("Using default API keys, if you want to use your own please make a config file.")

    vt_API = default_vt_API
    wf_API = default_wf_API
    ha_API = default_ha_API

    # print("config.json created, if you need to change your keys you can find your config in {}\\config.json".format(BASE_PATH))
except Exception as e:
    print("Config exists but couldn't read it {}".format(e))


# creating adapters for the request module, allows me to change the default timeout values
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


# set retry strategy for http requests
retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    method_whitelist=["GET", "POST", "PUT"],
    backoff_factor=2
)

adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)

# to_adapter = TimeoutHTTPAdapter(timeout=10)
# http.mount("https://", to_adapter)
# http.mount("http://", to_adapter)

# automatically trigger raise for status on requests so I don't have to do it manually everytime

assert_status_hook = lambda response,  \
    *args, **kwargs: response.raise_for_status()

http.hooks["response"] = [assert_status_hook]
