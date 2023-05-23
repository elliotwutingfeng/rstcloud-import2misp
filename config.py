#!/usr/bin/env python
# -*- coding: utf-8 -*-

rst_api_key = 'get_from_rstcloud'
misp_url = 'https://127.0.0.1/'  # change to the URL of your MISP server
# The MISP auth key can be created on the MISP web interface under the section http://[your_misp]/auth_keys/index
misp_key = 'create_in_your_misp'
misp_verifycert = False
misp_client_cert = ''
distribution_level = 0
# The levels are as follows:
# 0: Your Organisation Only
# 1: This Community Only
# 2: Connected Communities
# 3: All
# 4: Sharing Group
# 5: Inherit Event
import_filter = {
    "indicator_types": [
        "ip",
        "domain",
        "url",
        "hash"
    ],
    "score": {
        "ip": 40,
        "domain": 25,
        "url": 10,
        "hash": 10
    },
    "setIDS": {
        "ip": 55,
        "domain": 45,
        "url": 30,
        "hash": 10
    }
    }
publish = True
log_params = {
    "level": "DEBUG",
    "filename": "misp_uploader.log",
    "maxBytes": 1024*1024*10,
    "backupCount": 3
    }
