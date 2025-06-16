import os.path
import time
import json
import requests
import logging
import hashlib
import datetime
import os

base_url = 'https://www.virustotal.com/api/v3'

def get_VT_link(type, item):
    if type == "sha256":
        result = f'https://www.virustotal.com/gui/file/{item}'
    elif type == "ip":
        result = f'https://www.virustotal.com/gui/ip-address/{item}'
    elif type == "domain":
        result = f'https://www.virustotal.com/gui/domain/{item}'
    else:
        result = ""
    return result


def error_handle(response):
    '''
    The function returns True if there are no errors
    and returns False otherwise
    :param response: requests.models.Response
    :return: bool
    '''
    if response.status_code == 429:
        logging.warning("\t\t\t\tWAITING")
        time.sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
	    return True
    return False


def get_malicious_rank(vt_result):
    malicious_rank = -1
    try:
        if vt_result.get("data") is not None:
            if vt_result.get("data").get("attributes") is not None:
                if vt_result.get("data").get("attributes").get("last_analysis_stats") is not None:
                    if vt_result.get("data").get("attributes").get("last_analysis_stats").get("malicious") is not None:
                        malicious_rank = vt_result.get("data").get("attributes").get("last_analysis_stats").get("malicious")
                        logging.warning(f"Malicious rank fetched: {malicious_rank}")
    except Exception as err:
        logging.warning(f"An error occurred fetching the malicious rank from the data structure: {err}")
    return malicious_rank


def get_VT_categories(vt_result):
    VT_threat_class = ""
    VT_categories = []
    try:
        if vt_result.get("data") is not None:
            if vt_result.get("data").get("attributes") is not None:
                attributes = vt_result["data"]["attributes"]
                if attributes.get("popular_threat_classification") is not None:
                    if attributes.get("popular_threat_classification").get("suggested_threat_label") is not None:
                        VT_threat_class = attributes.get("popular_threat_classification").get("suggested_threat_label")
                    if attributes.get("popular_threat_classification").get("popular_threat_category") is not None:
                        for threat_category in attributes["popular_threat_classification"]["popular_threat_category"]:
                            VT_categories.append(threat_category["value"])

    except Exception as err:
        logging.warning(f"An error occurred fetching the VT category from the data structure: {err}")
    return VT_categories, VT_threat_class


'''
Analyze by hash. If the hash is not known, then send the file to VT
and wait for the analysis completion.
Once done, it resumes the analysis by hash
'''

def analysis_by_hash(api_key, file_path: str):
    logging.info("\t---> VT ANALYSIS BY HASH <---")

    headers = {'x-apikey': f'{api_key}'}
    sha256_hash = hashlib.sha256()
    if os.path.isfile(file_path):
        a_file = open(file_path, "rb")
        content = a_file.read()
        sha256_hash.update(content)
        digest = sha256_hash.hexdigest()
        a_file.close()
    else:
        return -1
    logging.info("\t\tFile digest: " + digest)

    logging.info("\t\tFetching hash report...")
    response = requests.get(base_url + '/files/' + digest, headers=headers)
    hash_report = response.json()
    logging.info(f"\t\tFirst hash report received from VT with code: {response}.")

    if "error" in hash_report:
        logging.info("\t\tVT ANALYSIS BY HASH WAS NOT SUCCESSFUL: trying to upload the file...")
        # submit the hash of the file
        response = requests.post(base_url + '/files/' + digest + '/analyse', headers=headers)
        # submit the file
        hash_received = analysis_by_file(api_key=api_key, file_path=file_path)
        logging.info(f"\t\tTrying to fetch the results by hash... Now VT has completed the analysis and returned this hash: {hash_received}.")
        response = requests.get(base_url + '/files/' + digest, headers=headers)
        hash_report = response.json()

    logging.info("\t\tVT ANALYSIS: Writing hash report comments...")
    response2 = requests.get(base_url + '/files/' + digest + '/comments', headers=headers)
    comments_report = response2.json()


    logging.info("\t\tVT ANALYSIS: Writing hash report behaviours...")
    response3 = requests.get(base_url + '/files/' + digest + '/behaviours', headers=headers)
    behaviours_report = response3.json()

    merged_report = {
        "hash_report": hash_report,
        "comments_report": comments_report,
        "behaviours_report": behaviours_report
    }
    
    logging.info("\t---> END OF VT HASH ANALYSIS <---\n")
    return json.dumps(merged_report, indent=4)


def analysis_by_file(api_key: str, file_path: str):
    headers = {'x-apikey': f'{api_key}'}

    # Send the file content to VT
    logging.info("\t\t\tVT ANALYSIS VIA FILE: reading the file and sending it to VT...")
    with open(file_path, 'rb') as file:
        file_content = file.read()
    files = {'file': (file_path, file_content)}
    while True:
        response = requests.post(base_url + '/files', headers=headers, files=files)
        if error_handle(response):
            break
    posted_id = response.json().get("data").get("id")
    logging.info(f"\t\t\tVT ANALYSIS VIA FILE: send completed and response is now available: {response} with {posted_id}. Waiting for the analysis.")

    # received response: now waiting for the analysis
    while True:
        logging.info("\t\t\t...Waiting analysis report...")
        time.sleep(60)
        while True:
            response = requests.get(base_url + '/analyses/' + posted_id, headers=headers)
            if error_handle(response):
                break
        logging.info(f"\t\t\t...Result of the GET response: {response}")
        if response.json().get("data").get("attributes").get("status") == "completed":
            file_report = response.json()
            logging.info("\t\t\tAnalysis via file completed successfully.")
            logging.info("\t\t---> END OF VT ANALYSIS BY FILE <---\n\n")
            return json.dumps(file_report, indent=4)

    return


'''
Analyze by IP.
'''
def analyze_ip_with_VT(api_key: str, ip: str):
    headers = {'x-apikey': f'{api_key}'}
    logging.info(f"\t---> VT ANALYSIS BY IP: {ip} <---")
    logging.info(f"\t\tIP analysis result file related to {ip} does not exist. Creating it...")
    logging.info(f"\t\tSending an IP request to VT...")
    while True:
        response = requests.get(base_url + '/ip_addresses/' + ip, headers=headers)
        if error_handle(response):
            break
    report_ip_content = response.json()
    logging.info(f"\t\tIP report obtained! Returning the IP report content...")
    logging.info("\t---> END OF VT ANALYSIS BY IP <---")
    return json.dumps(report_ip_content, indent=4)

'''
Analyze by domain.
'''
def analyze_domain_with_VT(api_key: str, domain: str):
    headers = {'x-apikey': f'{api_key}'}
    logging.info(f"\t---> VT ANALYSIS BY DOMAIN: {domain} <---")

    while True:
        response = requests.get(base_url + '/domains/' + domain, headers=headers)
        if error_handle(response):
            break
    report_domain_content = response.json()
    return json.dumps(report_domain_content, indent=4)