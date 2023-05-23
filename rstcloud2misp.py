import requests
import tempfile
from clint.textui import progress
import json
from datetime import datetime
import logging
import logging.handlers
import json
import gzip

from pymisp import PyMISP, MISPEvent, MISPOrganisation
from config import misp_url, misp_key, misp_verifycert, rst_api_key, distribution_level, publish, import_filter, log_params
import argparse

RST_API_URL = 'https://api.rstcloud.net/v1/'
HEADERS = {'Accept': 'application/json', 'X-Api-Key': rst_api_key}


def init(url, key):
    return PyMISP(url, key, misp_verifycert)

def listToString(s):
    if isinstance(s, list):
        delimiter = " | " 
        return (delimiter.join(s)) 
    elif isinstance(s, str):
        return (s) 

def download_files():
    file_urls = import_filter['indicator_types']
    data = {}
    for url in file_urls:
        logger.info(f'Downloading {url} feed')
        data[url] = download_feed(
            f'{RST_API_URL}{url}?type=json&date=latest', HEADERS)
    return data


def download_feed(URL, HEADERS):
    data = []
    r = requests.get(URL, headers=HEADERS, stream=True)
    with tempfile.TemporaryFile() as f:
        total_length = int(r.headers.get('content-length'))
        for chunk in progress.bar(r.iter_content(chunk_size=1024), label=f'{URL} - ', expected_size=(total_length/1024) + 1):
            if chunk:
                f.write(chunk)
                f.flush()
        f.seek(0)
        with gzip.open(f, 'rt') as file:
            for line in file:
                # if the last line is empty or corrupted, then skip
                try:
                    data.append(json.loads(line))
                except:
                    pass
    return data


def create_misp_event(name, data):
    org = MISPOrganisation()
    org.name = "RST Cloud"
    org.uuid = "b170e410-0b7c-4ae0-a676-89564e7a6178"
    event = MISPEvent()
    event.info = f"[RST Cloud] {datetime.now().date().isoformat()} Threat Feed for: {name}"
    event.Orgc = org
    event.distribution = distribution_level
    event.timestamp = datetime.now()
    event.add_tag(f'rstcloud:threat:name={name}')
    event.analysis = 2  # 0=initial; 1=ongoing; 2=completed
    event.threat_level_id = 2  # 1 = high ; 2 = medium; 3 = low; 4 = undefined
    # Limited disclosure, restricted to participants’ organization and its clients
    event.add_tag('tlp:amber')
    # add attributes to the new event
    for entry in data:
        TAG = ['tlp:amber']
        for threat in entry['threat']:
            TAG.append("rstcloud:threat:name=" + threat)
        for rsttag in entry['tags']['str']:
            TAG.append("rstcloud:category:name=" + str(rsttag))
        if "asn" in entry and "cloud" in entry['asn'] and entry['asn']['cloud']:
            TAG.append("rstcloud:cloudprovider:name=" + str(entry['asn']['cloud']))
            
        # Uncomment to get more tags. May impact performance
        #
        # if "asn" in entry and "num" in entry['asn'] and entry['asn']['num']:
        #     TAG.append("rstcloud:asn:id=" + str(entry['asn']['num']))
        # if "asn" in entry and "domains" in entry['asn'] and entry['asn']['domains']:
        #     TAG.append("rstcloud:related_domains:number=" + str(entry['asn']['domains']))
        if "asn" in entry and "org" in entry['asn'] and entry['asn']['org']:
            TAG.append("rstcloud:org:name="+str(entry['asn']['org']))
        if "asn" in entry and "isp" in entry['asn'] and entry['asn']['isp']:
            TAG.append("rstcloud:isp:name="+str(entry['asn']['isp']))
        
        # Uncomment to get more tags. May impact performance
        #
        # if "geo" in entry and "city" in entry['geo'] and entry['geo']['city']:
        #     TAG.append("rstcloud:geo:city=" + str(entry['geo']['city']))
        # if "geo" in entry and "region" in entry['geo'] and entry['geo']['region']:
        #     TAG.append("rstcloud:geo:region=" + str(entry['geo']['region']))
        if "geo" in entry and "country" in entry['geo'] and entry['geo']['country']:
            TAG.append("rstcloud:geo:country=" + str(entry['geo']['country']))
        if 'resolved' in entry and 'status' in entry['resolved'] and entry['resolved']['status']>0:
            TAG.append("rstcloud:http:status=" + str(entry['resolved']['status']))
        if 'resolved' in entry and 'whois' in entry['resolved']:
            # Uncomment to get more tags. May impact performance
            #
            # if entry['resolved']['whois']['age'] > 0:
            #     TAG.append("rstcloud:whois:created=" + str(entry['resolved']['whois']['created']))
            #     TAG.append("rstcloud:whois:updated=" + str(entry['resolved']['whois']['updated']))
            #     TAG.append("rstcloud:whois:expires=" + str(entry['resolved']['whois']['expires']))
            #     TAG.append("rstcloud:whois:age=" + str(entry['resolved']['whois']['age']))
            if entry['resolved']['whois']['registrar'] and entry['resolved']['whois']['registrar'] != 'unknown':
                TAG.append("rstcloud:whois:registrar=" + str(entry['resolved']['whois']['registrar']))
            if entry['resolved']['whois']['registrar'] and entry['resolved']['whois']['registrant'] != 'unknown':
                TAG.append("rstcloud:whois:registrant=" + str(entry['resolved']['whois']['registrant']))

        TAG.append("rstcloud:score:total=" + str(entry["score"]["total"]))
        TAG.append("rstcloud:false-positive:alarm=" + str(entry['fp']['alarm']))
        if entry['fp']['descr']:
            TAG.append("rstcloud:false-positive:description="+str(entry['fp']['descr']))
        if len(entry['cve']) > 0 and entry['cve']:
            for cve in entry['cve']:
                TAG.append("rstcloud:cve:id=" + cve.upper())
        if len(entry['industry']) > 0 and entry['industry']:
            for industry in entry['industry']:
                TAG.append("rstcloud:industry:name=" + industry)
        FSEEN = datetime.fromtimestamp(entry['fseen'])
        LSEEN = datetime.fromtimestamp(entry['fseen'])
        COMMENT = entry['description']

        if entry['src'] and entry['src']['report'] and len(entry['src']['report']) > 0:
            COMMENT += " | "
            COMMENT += listToString(entry['src']['report'] )
        IDS = False
        if 'ip' in entry:
            if entry["score"]["total"] > import_filter['setIDS']['ip']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('ip-dst', to_ids=IDS, value=entry['ip']['v4'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)
        if 'domain' in entry:
            if entry["score"]["total"] > import_filter['setIDS']['domain']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('domain', to_ids=IDS, value=entry['domain'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)
        if 'url' in entry:
            if entry["score"]["total"] > import_filter['setIDS']['url']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('url', to_ids=IDS, value=entry['url'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)
        if 'md5' in entry and len(entry['md5']) > 0:
            if entry["score"]["total"] > import_filter['setIDS']['hash']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('md5', to_ids=IDS, value=entry['md5'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)
        if 'sha1' in entry and len(entry['sha1']) > 0:
            if entry["score"]["total"] > import_filter['setIDS']['hash']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('sha1', to_ids=IDS, value=entry['sha1'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)
        if 'sha256' in entry and len(entry['sha256']) > 0:
            if entry["score"]["total"] > import_filter['setIDS']['hash']:
                IDS = True
            if entry["score"]["total"] > import_filter['score']['ip']:
                event.add_attribute('sha256', to_ids=IDS, value=entry['sha256'], first_seen=FSEEN, last_seen=LSEEN, Tag=TAG, comment=COMMENT)

    # add to the database and publish
    event = misp.add_event(event)
    if publish:
        misp.publish(event)


def process_files(data):
    logger.debug("Processing the feeds")
    # this to contain all indicators grouped by a threat name
    container_dict = {}

    for feed in data:
        for indicator in data[feed]:
            threats = indicator.get('threat', [])
            if threats:
                for threat in threats:
                    if not threat.endswith(('_tool', '_group', '_technique', '_vuln')):
                        container_dict.setdefault(threat, []).append(indicator)
    logger.info("The feeds have been processed. Found {} threats to be converted".format(len(container_dict)))
    return container_dict


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create MISP events containing domain|ip|url|hash attributes received from RST Cloud')
    parser.add_argument("-l", "--loglevel", type=str, help="Select a logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    args = parser.parse_args()

    logger = logging.getLogger('rst')
    ch = logging.handlers.RotatingFileHandler(log_params["filename"], maxBytes=log_params["maxBytes"], backupCount=log_params["backupCount"])
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(processName)s] [%(funcName)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if args.loglevel is None:
        if log_params['level'] in valid_log_levels:
            logger.setLevel(getattr(logging, log_params['level']))
        else:
            parser.error(f"Invalid log level: {log_params['level']}")
    else:
        
        if args.loglevel in valid_log_levels:
            logger.setLevel(getattr(logging, args.loglevel))
        else:
            parser.error(f"Invalid log level: {args.loglevel}")
    data = download_files()
    processed_data = process_files(data)
    misp = init(misp_url, misp_key)
    for threat in processed_data:
        logger.debug(f'Publishing an event for {threat}')
        create_misp_event(threat, processed_data[threat])
