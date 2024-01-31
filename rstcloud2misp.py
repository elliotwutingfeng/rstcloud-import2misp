import requests
import tempfile
from clint.textui import progress
import json
from datetime import datetime
import logging
import logging.handlers
import gzip
import uuid

from pymisp import PyMISP, MISPEvent, MISPOrganisation, MISPObject
from config import (
    misp_url,
    misp_key,
    misp_verifycert,
    rst_api_key,
    distribution_level,
    publish,
    import_filter,
    log_params,
    import_extra_data,
    merge_strategy,
    path_to_mitre_json,
    filter_strategy,
)
import argparse

import urllib3

urllib3.disable_warnings()

RST_API_URL = "https://api.rstcloud.net/v1/"
HEADERS = {"Accept": "application/json", "X-Api-Key": rst_api_key}


def init(url, key):
    return PyMISP(url, key, misp_verifycert)


def load_json_data(file_path):
    with open(file_path, "r", encoding="UTF-8") as file:
        data = json.load(file)
    return data


def lookup_value(json_data, key):
    results = [
        item["value"]
        for item in json_data["values"]
        if key == item["meta"]["external_id"]
    ]
    return results[0]


def download_files():
    file_urls = import_filter["indicator_types"]
    data = {}
    for url in file_urls:
        logger.info(f"Downloading {url} feed")
        data[url] = download_feed(f"{RST_API_URL}{url}?type=json&date=latest", HEADERS)
    return data


def download_feed(URL, HEADERS):
    data = []
    r = requests.get(URL, headers=HEADERS, stream=True)
    with tempfile.TemporaryFile() as f:
        total_length = int(r.headers.get("content-length"))
        for chunk in progress.bar(
            r.iter_content(chunk_size=1024),
            label=f"{URL} - ",
            expected_size=(total_length / 1024) + 1,
        ):
            if chunk:
                f.write(chunk)
                f.flush()
        f.seek(0)
        with gzip.open(f, "rt") as file:
            for line in file:
                # if the last line is empty or corrupted, then skip
                try:
                    data.append(json.loads(line))
                except:
                    pass
    return data


def check_if_event_exists(misp, name, merge):
    event_info = generate_event_info(merge, name)
    result = misp.search(controller="events", eventinfo=event_info)
    if len(result) > 0:
        return True
    else:
        return False


def format_tag(name, value):
    return f'{name}="{value}"'


# Generates event.info for a MISP Event based on a seclected merge strategy
# for a given threat name
def generate_event_info(merge, name):
    event_prefix = "[RST Cloud] Threat Feed"
    if merge == "threat_by_day":
        event_prefix = f"{event_prefix} {datetime.now().date().isoformat()}"
    elif merge == "threat_by_month":
        event_prefix = f"{event_prefix} {datetime.now().strftime('%Y-%m')}"
    elif merge == "threat_by_year":
        event_prefix = f"{event_prefix} {datetime.now().strftime('%Y')}"
    else:
        pass
    return f"{event_prefix}: {name}"


def check_for_hash(entry):
    if (
        "md5" in entry
        and len(entry["md5"]) > 0
        or "sha1" in entry
        and len(entry["sha1"]) > 0
        or "sha256" in entry
        and len(entry["sha256"]) > 0
    ):
        return True
    else:
        return False


def threat_tag_mapping(threat):
    if threat.endswith("_group"):
        return format_tag("misp-galaxy:threat-actor", threat.replace("_group", ""))
    elif threat.endswith("_tool"):
        return format_tag("misp-galaxy:tool", threat.replace("_tool", ""))
    elif threat.endswith("_stealer"):
        return format_tag("misp-galaxy:stealer", threat.replace("_stealer", ""))
    elif threat.endswith("_backdoor"):
        return format_tag("misp-galaxy:backdoor", threat.replace("_backdoor", ""))
    elif threat.endswith("_ransomware"):
        return format_tag("misp-galaxy:ransomware", threat.replace("_ransomware", ""))
    elif threat.endswith("_miner"):
        return format_tag("misp-galaxy:cryptominers", threat.replace("_miner", ""))
    elif threat.endswith("_exploit"):
        return format_tag("misp-galaxy:exploit-kit", threat.replace("_exploit", ""))
    elif threat.endswith("_backdoor"):
        return format_tag("misp-galaxy:backdoor", threat.replace("_backdoor", ""))
    elif threat.endswith("_botnet"):
        return format_tag("misp-galaxy:botnet", threat.replace("_botnet", ""))
    elif threat.endswith("_rat"):
        return format_tag("misp-galaxy:rat", threat.replace("_rat", ""))
    else:
        return format_tag("rstcloud:threat:name", threat)


def add_ref_update_event(REF, event, object):
    for ref in REF:
        object.add_attribute(
            "text", value=ref, comment="reference to the original source"
        )
    event.add_object(object)
    return event


def bundle_misp_event(name, data, merge, filter, extra):
    org = MISPOrganisation()
    org.name = "RST Cloud"
    org.uuid = "b170e410-0b7c-4ae0-a676-89564e7a6178"
    event = MISPEvent()
    event.info = generate_event_info(merge, name)
    event.Orgc = org
    event.uuid = uuid.uuid5(
        uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), event.info
    )
    event.distribution = distribution_level
    event.timestamp = datetime.now()
    event_tag = threat_tag_mapping(name)
    if "rstcloud" not in event_tag:
        # tag using misp galaxy notation
        event.add_tag(event_tag)
        event.add_tag(format_tag("rstcloud:threat:name", name))
    else:
        # tag with rstcloud names for search consistency for all rst data
        event.add_tag(event_tag)
    event.analysis = 2  # 0=initial; 1=ongoing; 2=completed
    event.threat_level_id = 2  # 1 = high ; 2 = medium; 3 = low; 4 = undefined
    # Limited disclosure, restricted to participants’ organisation and its clients
    event.add_tag("tlp:amber")
    # add attributes to the new event
    for entry in data:
        FSEEN = datetime.fromtimestamp(entry["fseen"]).date()
        LSEEN = datetime.fromtimestamp(entry["lseen"]).date()
        COMMENT = ""
        REF = []
        IDS = False
        if filter != "all":
            if filter == "recent":
                if not ((entry["collect"] - entry["lseen"]) == 0):
                    continue
            if filter == "only_new":
                if not ((entry["collect"] - entry["fseen"]) == 0):
                    continue
        TAG = ["tlp:amber"]
        for threat in entry["threat"]:
            TAG.append(threat_tag_mapping(threat))
        for rsttag in entry["tags"]["str"]:
            TAG.append(format_tag("rstcloud:category:name", rsttag))

        TAG.append(format_tag("rstcloud:score:total", entry["score"]["total"]))

        if entry["fp"] and entry["fp"]["alarm"]:
            if entry["fp"]["alarm"] == "true":
                TAG.append('false-positive:risk="high"')
            elif entry["fp"]["alarm"] == "possible":
                TAG.append('false-positive:risk="medium"')
            elif entry["fp"]["alarm"] == "false":
                TAG.append('false-positive:risk="low"')
            else:
                TAG.append('false-positive:risk="cannot-be-judged"')

        if entry["fp"]["descr"]:
            COMMENT = str(entry["fp"]["descr"])
        if len(entry["cve"]) > 0 and entry["cve"]:
            for cve in entry["cve"]:
                TAG.append(format_tag("rstcloud:cve:id", cve.upper()))
        if len(entry["ttp"]) > 0:
            for ttp_id in entry["ttp"]:
                try:
                    TAG.append(
                        format_tag(
                            "misp-galaxy:mitre-attack-pattern",
                            lookup_value(mitre_ttps, ttp_id.upper()),
                        )
                    )
                except Exception as ex:
                    logger.error(
                        f"Error while looking up the MITRE tag {ttp_id.upper()}: {str(ex)}"
                    )
        if len(entry["industry"]) > 0 and entry["industry"]:
            for industry in entry["industry"]:
                TAG.append(format_tag("misp-galaxy:sector", industry))

        if entry["src"] and entry["src"]["report"] and len(entry["src"]["report"]) > 0:
            # extract references
            REF = entry["src"]["report"].split(",")
            # remove duplicates
            REF = list(dict.fromkeys(REF))

        if "ip" in entry:
            # only process if it needs to be imported
            if entry["score"]["total"] > import_filter["score"]["ip"]:
                object = MISPObject("ip-port")
                # check for detection if the score is high enough
                if entry["score"]["total"] > import_filter["setIDS"]["ip"]:
                    IDS = True
                object.add_attribute(
                    "ip",
                    to_ids=IDS,
                    value=entry["ip"]["v4"],
                    first_seen=FSEEN,
                    last_seen=LSEEN,
                    Tag=TAG,
                    comment=COMMENT,
                )
                if "asn" in entry and "num" in entry["asn"] and entry["asn"]["num"]:
                    object.add_attribute("AS", value=entry["asn"]["num"])
                    if extra:
                        object.add_attribute(
                            "text", value=str(entry["asn"]), disable_correlation=True
                        )
                if (
                    "geo" in entry
                    and "country" in entry["geo"]
                    and entry["geo"]["country"]
                ):
                    object.add_attribute("country-code", value=entry["geo"]["country"])
                    if extra:
                        object.add_attribute(
                            "text", value=str(entry["geo"]), disable_correlation=True
                        )
                if (
                    "ports" in entry
                    and len(entry["ports"]) > 0
                    and entry["ports"][0] != -1
                ):
                    for port in entry["ports"]:
                        object.add_attribute("dst-port", value=port)
                event = add_ref_update_event(REF, event, object)
        if "domain" in entry:
            if entry["score"]["total"] > import_filter["score"]["domain"]:
                object = MISPObject("domain-ip")
                if entry["score"]["total"] > import_filter["setIDS"]["domain"]:
                    IDS = True
                object.add_attribute(
                    "domain",
                    to_ids=IDS,
                    value=entry["domain"],
                    first_seen=FSEEN,
                    last_seen=LSEEN,
                    Tag=TAG,
                    comment=COMMENT,
                )
                if (
                    "ports" in entry
                    and len(entry["ports"]) > 0
                    and entry["ports"][0] != -1
                ):
                    for port in entry["ports"]:
                        object.add_attribute("port", value=port)
                if "resolved" in entry and "whois" in entry["resolved"]:
                    object.add_attribute(
                        "text",
                        value=str(entry["resolved"]["whois"]),
                        comment="Whois Info",
                        disable_correlation=True,
                    )
                if "resolved" in entry and "ip" in entry["resolved"]:
                    if (
                        "a" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["a"]) > 0
                    ):
                        for resolved_a in entry["resolved"]["ip"]["a"]:
                            object.add_attribute(
                                "ip",
                                to_ids=False,
                                value=resolved_a,
                                first_seen=FSEEN,
                                last_seen=LSEEN,
                                comment=f'DNS to IP result for {entry["domain"]}',
                            )
                    if (
                        "cname" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["cname"]) > 0
                    ):
                        for resolved_cname in entry["resolved"]["ip"]["cname"]:
                            object.add_attribute(
                                "domain",
                                to_ids=False,
                                value=resolved_cname,
                                first_seen=FSEEN,
                                last_seen=LSEEN,
                                comment=f'a CNAME for DNS to IP result for {entry["domain"]}',
                            )
                    if (
                        "alias" in entry["resolved"]["ip"]
                        and len(entry["resolved"]["ip"]["alias"]) > 0
                    ):
                        for resolved_alias in entry["resolved"]["ip"]["alias"]:
                            object.add_attribute(
                                "domain",
                                to_ids=False,
                                value=resolved_alias,
                                first_seen=FSEEN,
                                last_seen=LSEEN,
                                comment=f'an Alias for DNS to IP result for {entry["domain"]}',
                            )

                event = add_ref_update_event(REF, event, object)
        if "url" in entry:
            if entry["score"]["total"] > import_filter["score"]["url"]:
                object = MISPObject("url")
                if entry["score"]["total"] > import_filter["setIDS"]["url"]:
                    IDS = True
                object.add_attribute(
                    "url",
                    to_ids=IDS,
                    value=entry["url"],
                    first_seen=FSEEN,
                    last_seen=LSEEN,
                    Tag=TAG,
                    comment=COMMENT,
                )
                if (
                    "resolved" in entry
                    and "status" in entry["resolved"]
                    and entry["resolved"]["status"] > 0
                ):
                    object.add_attribute(
                        "text",
                        value=str(entry["resolved"]["status"]),
                        comment="HTTP Status of the URL",
                        disable_correlation=True,
                    )
                if "parsed" in entry:
                    u = entry["parsed"]
                    object.add_attribute("scheme", value=str(u["schema"]))
                    object.add_attribute(
                        "domain",
                        to_ids=False,
                        value=u["domain"],
                        first_seen=FSEEN,
                        last_seen=LSEEN,
                    )
                    object.add_attribute("resource_path", value=str(u["path"]))
                    object.add_attribute("query_string", value=str(u["params"]))
                event = add_ref_update_event(REF, event, object)
        if check_for_hash(entry):
            if entry["score"]["total"] > import_filter["score"]["hash"]:
                if entry["score"]["total"] > import_filter["setIDS"]["hash"]:
                    IDS = True
                object = MISPObject("file")
                if "filename" in entry and entry["filename"]:
                    for name in entry["filename"]:
                        object.add_attribute(
                            "filename",
                            to_ids=IDS,
                            value=name,
                            first_seen=FSEEN,
                            last_seen=LSEEN,
                            Tag=TAG,
                            comment=COMMENT,
                        )
                if "md5" in entry and len(entry["md5"]) > 0:
                    object.add_attribute(
                        "md5",
                        to_ids=IDS,
                        value=entry["md5"],
                        first_seen=FSEEN,
                        last_seen=LSEEN,
                        Tag=TAG,
                        comment=COMMENT,
                    )
                if "sha1" in entry and len(entry["sha1"]) > 0:
                    object.add_attribute(
                        "sha1",
                        to_ids=IDS,
                        value=entry["sha1"],
                        first_seen=FSEEN,
                        last_seen=LSEEN,
                        Tag=TAG,
                        comment=COMMENT,
                    )
                if "sha256" in entry and len(entry["sha256"]) > 0:
                    object.add_attribute(
                        "sha256",
                        to_ids=IDS,
                        value=entry["sha256"],
                        first_seen=FSEEN,
                        last_seen=LSEEN,
                        Tag=TAG,
                        comment=COMMENT,
                    )
                event = add_ref_update_event(REF, event, object)
    logger.debug(f"Found {len(event.objects)} objects")
    return event


def create_misp_event(name, data, merge, filter, extra):
    try:
        misp_event = bundle_misp_event(name, data, merge, filter, extra)
        # add to the database and publish
        if len(misp_event.objects) > 0:
            event = misp.add_event(misp_event, metadata=True)
            if publish:
                misp.publish(event)
    except Exception as ex:
        logger.error(f"create_misp_event: {ex}")


def update_misp_event(name, data, merge, filter, extra):
    try:
        misp_event = bundle_misp_event(name, data, merge, filter, extra)
        # update the event and publish
        if len(misp_event.objects) > 0:
            event = misp.update_event(misp_event, metadata=True)
            if publish:
                misp.publish(event)
    except Exception as ex:
        logger.error(f"create_misp_event: {ex}")


def process_files(data):
    logger.debug("Processing the feeds")
    # this to contain all indicators grouped by a threat name
    container_dict = {}

    for feed in data:
        for indicator in data[feed]:
            threats = indicator.get("threat", [])
            if threats:
                for threat in threats:
                    if not threat.endswith(
                        ("_tool", "_group", "_technique", "_vuln", "_campaign")
                    ):
                        container_dict.setdefault(threat, []).append(indicator)
    logger.info(
        f"The feeds have been processed. Found {len(container_dict)} threats to be converted"
    )
    return container_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create MISP events containing domain|ip|url|hash attributes received from RST Cloud"
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        type=str,
        help="Select a logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )
    args = parser.parse_args()

    logger = logging.getLogger("rst")
    ch = logging.handlers.RotatingFileHandler(
        log_params["filename"],
        maxBytes=log_params["maxBytes"],
        backupCount=log_params["backupCount"],
    )
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(processName)s] [%(funcName)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    valid_merge_strategies = [
        "threat_by_day",
        "threat_by_month",
        "threat_by_year",
        "threat",
    ]
    valid_filter_strategies = ["all", "recent", "only_new"]
    valid_extra_values = ["false", "true", "False", "True", "1", "0"]

    if args.loglevel is None:
        if log_params["level"] in valid_log_levels:
            logger.setLevel(getattr(logging, log_params["level"]))
        else:
            parser.error("Invalid log level")
    else:
        if args.loglevel in valid_log_levels:
            logger.setLevel(getattr(logging, args.loglevel))
        else:
            parser.error("Invalid log level")

    merge = "threat"
    if merge_strategy and merge_strategy in valid_merge_strategies:
        merge = merge_strategy
    else:
        parser.error("Invalid merge strategy")

    filter = "recent"
    if filter_strategy and filter_strategy in valid_filter_strategies:
        filter = filter_strategy
    else:
        parser.error("Invalid filter strategy")

    extra = False
    if type(import_extra_data) is bool:
        if import_extra_data:
            extra = True
    else:
        parser.error("Invalid import_extra_data")

    misp = init(misp_url, misp_key)

    mitre_ttps = load_json_data(path_to_mitre_json)
    data = download_files()
    processed_data = process_files(data)

    for threat in processed_data:
        logger.debug(f"Publishing an event for {threat}")
        if merge == "threat_by_day":
            event = check_if_event_exists(misp, threat, merge)
            if event:
                logger.info(f"Skipping the event for {threat} to avoid duplication")
            else:
                create_misp_event(threat, processed_data[threat], merge, filter, extra)
        elif (
            merge == "threat" or merge == "threat_by_month" or merge == "threat_by_year"
        ):
            event = check_if_event_exists(misp, threat, merge)
            if event:
                update_misp_event(threat, processed_data[threat], merge, filter, extra)
            else:
                create_misp_event(threat, processed_data[threat], merge, filter, extra)
        else:
            logger.error("Unknown merging strategy")
            exit(1)
    logger.info("Finished publishing MISP events")
