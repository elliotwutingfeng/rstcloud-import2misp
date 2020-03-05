import requests
import tempfile
from clint.textui import progress
import json
from datetime import datetime

from pymisp import PyMISP, MISPEvent, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert
import argparse

# user-defined settings
USER='YOURUSERNAME'
PASS='YOURPASSWORD'
distribution_level = 0
PUBLISH = True
# The levels are as follows:
# 0: Your Organisation Only
# 1: This Community Only
# 2: Connected Communities
# 3: All
# 4: Sharing Group
# 5: Inherit Event
DOMAIN_URL='https://ioc.rstcloud.net/static/v1/full/ioc_domain_latest_full.json'
IP_URL='https://ioc.rstcloud.net/static/v1/full/ioc_ip_latest_full.json'

# other variables
HEADERS={'Accept': 'application/json' }

def init(url, key):
    return PyMISP(url, key, misp_verifycert)
    # replace to enable json debug
    #return PyMISP(url, key, misp_verifycert,'json')

def listToString(s):  
    delimiter = ", " 
    return (delimiter.join(s)) 

def domain_attribute(category, type, value):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = type
    attribute.value = value['domain']
    attribute.comment = listToString(value['src']['str'])
    attribute.first_seen = value['fseen']
    attribute.last_seen = value['lseen']
    attribute.timestamp = value['collect']
    attribute.distribution = distribution_level
    attribute.add_tag("rstcloud:score:total="+str(value['score']['total']))
    for rsttag in value['tags']['str']:
        attribute.add_tag("rstcloud:tag="+str(rsttag))
    if value['resolved'] and value['resolved']['whois']:
        if value['resolved']['whois']['age'] > 0:
            attribute.add_tag("rstcloud:whois:created="+str(value['resolved']['whois']['created']))
            attribute.add_tag("rstcloud:whois:updated="+str(value['resolved']['whois']['updated']))
            attribute.add_tag("rstcloud:whois:expires="+str(value['resolved']['whois']['expires']))
            attribute.add_tag("rstcloud:whois:age="+str(value['resolved']['whois']['age']))
        if value['resolved']['whois']['registrar'] and value['resolved']['whois']['registrar'] != 'unknown':
            attribute.add_tag("rstcloud:whois:registrar="+str(value['resolved']['whois']['registrar']))
        if value['resolved']['whois']['registrar'] and value['resolved']['whois']['registrant'] != 'unknown':
            attribute.add_tag("rstcloud:whois:registrant="+str(value['resolved']['whois']['registrant']))
    attribute.add_tag("rstcloud:score:total="+str(value['score']['total']))
    attribute.add_tag("rstcloud:false-positive:alarm="+str(value['fp']['alarm']))
    if value['fp']['descr']:
        attribute.add_tag("rstcloud:false-positive:description="+str(value['fp']['descr']))
    return attribute

def ip_attribute(category, type, value):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.org = "RST Cloud"
    attribute.type = type
    if value['ip']:
        if value['ip']['v4']:
            attribute.value = value['ip']['v4']
            attribute.add_tag("rstcloud:asn:firstip="+str(value['asn']['firstip']['netv4']))
            attribute.add_tag("rstcloud:asn:lastip="+str(value['asn']['lastip']['netv4']))
        else:
            if value['ip']['v6']:
                attribute.value = value['ip']['v6']
                attribute.add_tag("rstcloud:asn:firstip="+str(value['asn']['firstip']['netv6']))
                attribute.add_tag("rstcloud:asn:lastip="+str(value['asn']['lastip']['netv6']))
    
    attribute.add_tag("rstcloud:asn:number="+str(value['asn']['num']))        
    attribute.comment = listToString(value['src']['str'])
    attribute.first_seen = value['fseen']
    attribute.last_seen = value['lseen']
    attribute.timestamp = value['collect']
    attribute.distribution = distribution_level
    attribute.add_tag("rstcloud:score:total="+str(value['score']['total']))
    for rsttag in value['tags']['str']:
        attribute.add_tag("rstcloud:tag="+str(rsttag))  
    if value['asn']['cloud']:
        attribute.add_tag("rstcloud:cloudprovider="+str(value['asn']['cloud']))
    if value['asn']['domains']:
        attribute.add_tag("rstcloud:number_of_hosted_domains="+str(value['asn']['domains']))
    attribute.add_tag("rstcloud:org="+str(value['asn']['org']))
    attribute.add_tag("rstcloud:isp="+str(value['asn']['isp']))
    attribute.add_tag("rstcloud:geo.city="+str(value['geo']['city']))
    attribute.add_tag("rstcloud:geo.region="+str(value['geo']['region']))
    attribute.add_tag("rstcloud:geo.country="+str(value['geo']['country']))
    attribute.add_tag("rstcloud:score:total="+str(value['score']['total']))
    attribute.add_tag("rstcloud:false-positive:alarm="+str(value['fp']['alarm']))
    if value['fp']['descr']:
        attribute.add_tag("rstcloud:false-positive:description="+str(value['fp']['descr']))
    return attribute


def download_feed(URL,HEADERS,USER,PASS):
    data = []
    r = requests.get(URL, headers=HEADERS, auth=requests.auth.HTTPBasicAuth(USER, PASS), stream=True)
    with tempfile.TemporaryFile() as f:
        total_length = int(r.headers.get('content-length'))
        for chunk in progress.bar(r.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1): 
            if chunk:
                f.write(chunk)
                f.flush()
        f.seek(0)
        for line in f:
            # if the last line is empty or corrupted, then skip
            try:
                data.append(json.loads(line))
            except:
                pass
    return data
    
def create_event(FEED, type):
    #'uuid', 'info', 'threat_level_id', 'analysis', 'timestamp','publish_timestamp', 'published', 'date', 'extends_uuid'}
    event = MISPEvent()
    event.info = f"[{datetime.now().date().isoformat()}] RST Cloud Daily {type} feed"
    
    event.analysis=2 # 0=initial; 1=ongoing; 2=completed
    event.threat_level_id=2 #1 = high ; 2 = medium; 3 = low; 4 = undefined
    event.add_tag('tlp:white')
    
    # add to the database and publish    
    event = misp.add_event(event)
    if PUBLISH:
        misp.publish(event)
    
    # add attributes to the newly created event
    for entry in FEED:
        if type == 'Domain': 
            misp.add_attribute(event, domain_attribute('Network activity', 'domain', entry))
        if type == 'IP': 
            misp.add_attribute(event, ip_attribute('Network activity', 'ip-dst', entry))
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create an event with date in the name containing an domain|ip attributes received from RST Cloud')
    parser.add_argument("-f", "--feeds", type=str, default="domain", help="Feeds to download: all, domain, ip (default - all)")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.feeds is None:
        args.feeds = 'all'

    if (args.feeds == 'all' or args.feeds == 'domain'):
        # RST -> MISP Mapping:
        # domain -> domain
        # fseen -> first_seen
        # lseen -> last_seen
        # collect -> timestamp
        # src.str -> comment
        # src.codes - SKIP
        # tags.str -> tag - rstcloud:tag
        # tags.codes - SKIP
        # resolved.ip.a - SKIP
        # resolved.ip.alias - SKIP
        # resolved.ip.cname - SKIP
        # resolved.whois.created -> tag - rstcloud:whois:created
        # resolved.whois.updated -> tag - rstcloud:whois:updated
        # resolved.whois.expires -> tag - rstcloud:whois:expires
        # resolved.whois.age -> tag - rstcloud:whois:age
        # resolved.whois.registrar -> tag - rstcloud:whois:registrar
        # resolved.whois.registrant -> tag - rstcloud:whois:registrant
        # resolved.whois.havedata - SKIP
        # score.total -> tag - rstcloud:score:total
        # score.receive - SKIP
        # score.src - SKIP
        # score.tags - SKIP 
        # score.frequency - SKIP
        # fp.alarm -> tag - rstcloud:false-positive:alarm
        # fp.descr -> tag - rstcloud:false-positive:description
         
        DOMAIN_FEED = download_feed(DOMAIN_URL,HEADERS,USER,PASS)
        create_event(DOMAIN_FEED, 'Domain')
    
    if (args.feeds == 'all' or args.feeds == 'ip'): 
        # RST -> MISP Mapping:
        # ip.v4|v6 -> ip-dst
        # fseen -> first_seen
        # lseen -> last_seen
        # collect -> timestamp
        # src.str -> comment
        # src.codes - SKIP
        # tags.str ->
        # tags.codes - SKIP
        # asn.num ->  tag - rstcloud:asn:number
        # asn.firstip.netv4|netv6 -> tag - rstcloud:asn:firstip
        # asn.lastip.netv4|netv6 -> tag - rstcloud:asn:lastip
        # cloud -> tag - rstcloud:cloudprovider
        # domains -> tag - rstcloud:number_of_hosted_domains
        # org -> tag - rstcloud:org
        # isp -> tag - rstcloud:isp
        # geo.city -> tag - rstcloud:geo:city
        # geo.country -> tag - rstcloud:geo:country
        # geo.region -> tag - rstcloud:geo:region
        # related.domains - SKIP
        # score.total -> tag - rstcloud:score:total
        # score.receive - SKIP
        # score.src - SKIP
        # score.tags - SKIP
        # score.frequency - SKIP
        # fp.alarm -> tag - rstcloud:false-positive:alarm
        # fp.descr -> tag - rstcloud:false-positive:description
        # 
        IP_FEED = download_feed(IP_URL,HEADERS,USER,PASS)
        create_event(IP_FEED, 'IP')
    