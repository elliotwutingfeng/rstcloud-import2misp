#!/usr/bin/env python
# -*- coding: utf-8 -*-

rst_api_key = "get_from_rstcloud"
misp_url = "https://127.0.0.1/"  # change to the URL of your MISP server
# The MISP auth key can be created on the MISP web interface
# under the section http://[your_misp]/auth_keys/index
misp_key = "create_in_your_misp"
misp_verifycert = False
misp_client_cert = ""
distribution_level = 0
# The levels are as follows:
# 0: Your Organisation Only
# 1: This Community Only
# 2: Connected Communities
# 3: All
# 4: Sharing Group
# 5: Inherit Event
import_extra_data = True
path_to_mitre_json = "mitre-attack-pattern.json"
# merge_strategy="threat_by_day"
merge_strategy = "threat"

# filter_strategy="all" - import the whole feed
# filter_strategy="recent" - import only recent values (anything updated for the last 24 hours)
# filter_strategy="only_new" - import only new values (anyting new for the last 24 hours)
filter_strategy = "recent"
import_filter = {
    "indicator_types": ["ip", "domain", "url", "hash"],
    "score": {"ip": 40, "domain": 25, "url": 10, "hash": 10},
    "setIDS": {"ip": 55, "domain": 45, "url": 30, "hash": 15},
}
publish = True
log_params = {
    "level": "DEBUG",
    "filename": "misp_uploader.log",
    "maxBytes": 1024 * 1024 * 10,
    "backupCount": 3,
}
