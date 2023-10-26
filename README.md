# rstcloud-import2misp
The provided script facilitates the daily download of IoCs from RST Cloud and imports them into MISP for comprehensive analysis. Each day, a distinct event is created for each threat name. This results in a substantial number of events, such as 300 events for threats like Azorult, Redline Stealer, Emotet, Qakbot, Cobalt Strike, and others on one day, followed by 350 events on the next day, and so forth. This approach ensures that there is an abundance of valuable indicators and contextual information for each IoC, which are integrated into MISP as custom tags.

![RST Cloud events in MISP](/screenshot.png)
![RST Cloud attributes in MISP](/screenshot_attributes.png)

Use cron to configure the script to run daily from 12 am to 3 am UTC

To trial, please, contact us https://www.rstcloud.com/#free-trial

## Configuration
### Minimal

Obtain a key and populate the following variables in the file named config.py:

```
rst_api_key = 'a key received from RST Cloud'
misp_url = 'https://127.0.0.1/'
misp_key = 'a key generated in MISP'
```

Have a look at the *import_filter* in the file *config.py*. It allows to set a minimum score for each type of indicators to be pushed into MISP and also the minimum score required to be identified as actionable (to_ids=true)

Please choose a strategy how MISP events are to be created:
1) merge_strategy="threat"
    * default option
    * all indicators are grouped by a threat name
    * events tend to become bigger and bigger over time
2) merge_strategy="threat_by_day"
    * all indicators are grouped by a threat name per day
    * events are smaller but there are more of them (the worst case scenario is 365 events per each malware a year)
    * MISP correlation function may be impacting query performance  

### Advanced
Redefined import_filter variable to control what IoCs to import:
- indicator types: you can select from ip, domain, url, hash
- score: what RST Cloud's total score for an indicator is considered a minimum required fro the indicator to be imported into MISP. You can set it for each individual indicator type
- setIDS: what RST Cloud's total score for an indicator is considered a minimum required to be set with a flag IDS that usually is used in MISP for indicators you want to send for real-time detection or blocking

`publish = true` is used to automatically publish events. You will be getting info about hundreds of malware threats a day

MISP does not provide optimal storage options for certain types of contextual information, such as ASN (Autonomous System Number) and WHOIS data. Therefore, you may notice that these details are often commented out in the code `rstcloud2misp.py` to minimize the cardinality of the tags used in MISP. 
You have the option to uncomment some of those tags and evaluate if including them in your environment is acceptable. By doing so, you can assess the impact on performance and determine if it meets your requirements.