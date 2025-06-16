import requests
import urllib3
import os
import json
import sys
import datetime
from dateutil.parser import parse
from requests.adapters import HTTPAdapter, Retry
#import argparse

OTX_URL = "https://otx.alienvault.com"
OTX_API_v1 = "/api/v1/indicators"
OTX_API_website = "/otxapi/indicators"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def otx_scan(OTX_API_KEY, domain, proxy=None):
    type = ""

    # other interesting factors
    misc_facts = {}
    country_name = ""

    # Initialize requests session with 5 max retries and an increasing delay
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    s = requests.Session()
    s.headers = headers
    retries = Retry(total=5,
                backoff_factor=0.1,
                status_forcelist=[429, 500, 502, 503, 504])
    s.mount('https://', HTTPAdapter(max_retries=retries))

    # First API call to get the type among domain, hostname and ip
    type_endpoint = OTX_API_website + f"/exact_match?q={domain}"
    try:
        type_resp = s.get(OTX_URL + type_endpoint, proxies=proxy, verify=False)
        if type_resp.status_code == 200:
            type = type_resp.text.replace("\"", "")
    except requests.exceptions.RetryError as ex:
        print(ex)

    # Second API call to get the country
    country_endpoint = OTX_API_website + f"/url/analysis/{domain}"
    try:
        country_resp = s.get(OTX_URL + country_endpoint, proxies=proxy, verify=False)
        if country_resp.status_code == 200:
            country_name = country_resp.json().get("indicators").get("ip").get("country_name"); misc_facts["country_name"] = country_name
    except requests.exceptions.RetryError as ex:
        print(ex)

    analysis_endpoint_json = {}
    pulses_json = {}
    # Third API call to get most of the factors
    analysis_endpoint = OTX_API_website + f"/{type}/analysis/{domain}"
    try:
        analysis_resp = s.get(OTX_URL + analysis_endpoint, proxies=proxy, verify=False)
        if analysis_resp.status_code == 200:
            analysis_endpoint_json = analysis_resp.json()

    except requests.exceptions.RetryError as ex:
        return json.dumps({"error": "Too many error responses"}, indent=2)
    
    # Fourth API call to get pulses
    type = "IPv4" if type == "ip" else type
    general_endpoint = OTX_API_v1 + f"/{type}/{domain}/general"
    try:
        general_resp = s.get(OTX_URL + general_endpoint, proxies=proxy, verify=False)
        if general_resp.status_code == 200:
            pulses_json=general_resp.json()

    except requests.exceptions.RetryError as ex:
        print(ex)

    # Fifth API call to get malicious files
    malware_endpoint = OTX_API_v1 + f"/{type}/{domain}/malware"
    try:
        malware_resp = s.get(OTX_URL + malware_endpoint, proxies=proxy, verify=False)
        if malware_resp.status_code == 200:
            malicious_files = malware_resp.json()
    except requests.exceptions.RetryError as ex:
        print(ex)

    merged = {**pulses_json, **analysis_endpoint_json}

    return json.dumps(merged, indent=2)
