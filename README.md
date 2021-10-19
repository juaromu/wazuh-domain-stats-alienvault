# wazuh-domain-stats-alienvault
**WAZUH AND DOMAIN STATS + ALIENVAULT OTX**


[TOC]



## 


## Intro

Wazuh and Domain Stats Integration. New, first seen or suspicious domains checked against AlienVault OTX IoCs via Wazuh’s Active Response.

Wazuh 4.2 improved substantially its active response capabilities, above and beyond what was initially included in OSSEC. Now, as part of the active response communication with the agents the full alert (JSON) that triggered the response can be passed to the agent, who in turn can extract fields and use them as parameters for command executions.


## Domain Stats

GitHub Repo [here](https://github.com/MarkBaggett/domain_stats)

Created by Mark Baggett (SANS instructor).

Uses RDAP by default (Registration Data Access Protocol).

After install, it’ll allow you to download the “top1m” and store it in its internal database (SQLite DB used as a “cache”).

Once installed, enables a listener for HTTP conns (port 5730 by default). Calling this API with a hostname/domain as parameter will return valuable information for threat hunting purposes.


## AlienVault OTX

AlienVault Open Threat Exchange (OTX). is a community-based threat intel.

An API key can be obtained and allows a maximum of 10,000 requests per hour.

A caveat for this OTX is that the API returns IoCs found in pulses created by ALL users. This normally generates a lot of false positives. The script configured in the agents includes a filter to retain only IoCs part of pulses created by the user “AlienVault”. This filter can be modified to match pulses created by any user(s) in the platform. It’s also important to highlight that when IoCs are present in several pulses, the API response can be considerably long; to that event the script also processes the JSON response and selects key pairs relevant to the IoC(s) reported. This means that the alert generated will include relevant information to further analyse the IoCs found but it won’t include the full JSON response from the OTX.


## Workflow



1. Sysmon Event IDs = 22 will trigger a custom integration in the manager.
2. This integration (Python script) will call the DNS Stats API and it’ll evaluate its response:
    1. “First time seen” domains / Low Frequency domains / New created domains will generate an alert.
    2. This new alert will activate an active response script in the agent, who in turn, will make an API call to AlienVault’s OTX passing the queried hostname as parameter.
3.  If IoCs are found for the specific domain, the agent will insert an alert in its active responses log.

In this document, the Domain Stats packages are installed in the manager, but can be installed in any other server in your environment.

Wazuh Custom integration (ossec.conf)


```
<integration>
 <name>custom-dnsstats</name>
 <group>sysmon_event_22</group>
 <alert_format>json</alert_format>
</integration>
```


Files (/var/ossec/integrations folder):


```
-rwxr-x--- 1 root ossec  1025 Oct 19 10:52 custom-dnsstats
-rwxr-x--- 1 root ossec  2772 Oct 20 07:34 custom-dnsstats.py
```


Content of “custom-dnsstats”:


```
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```


Content of “custom-dnsstats.py”:


```
#!/usr/bin/env python
# Aurora Networks Managed Services
# https://www.auroranetworks.net
# info@auroranetworks.net.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:dns_stats:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->dns_stats:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if DNS Stat Alert or Error calling the API
alert_output = {}
# DNS Stats Base URL
dns_stats_base_url = 'http://127.0.0.1:5730/'
# Extract Queried Hostname from Sysmon Event
dns_query_name = alert["data"]["win"]["eventdata"]["queryName"]
dns_stats_url = ''.join([dns_stats_base_url, dns_query_name])
# DNS Stat API Call
try:
    dns_stats_response = requests.get(dns_stats_url)
except ConnectionError:
    alert_output["dnsstat"] = {}
    alert_output["integration"] = "dnsstat"
    alert_output["dnsstat"]["error"] = 'Connection Error to DNS Stats API'
    send_event(alert_output, alert["agent"])
else:
    dns_stats_response = dns_stats_response.json()
# Check if response includes alerts or New Domain
    if (dns_stats_response["alerts"] and dns_stats_response["category"] != 'ERROR') or  dns_stats_response["category"] == 'NEW':
# Generate Alert Output from DNS Stats Response
        alert_output["dnsstat"] = {}
        alert_output["integration"] = "dnsstat"
        alert_output["dnsstat"]["query"] = dns_query_name
        alert_output["dnsstat"]["alerts"] = dns_stats_response["alerts"]
        alert_output["dnsstat"]["category"] = dns_stats_response["category"]
        alert_output["dnsstat"]["freq_score"] = dns_stats_response["freq_score"]
        alert_output["dnsstat"]["seen_by_isc"] = dns_stats_response["seen_by_isc"]
        alert_output["dnsstat"]["seen_by_web"] = dns_stats_response["seen_by_web"]
        alert_output["dnsstat"]["seen_by_you"] = dns_stats_response["seen_by_you"]
        send_event(alert_output, alert["agent"])
```


Detection Rules for Domain STATS Alerts (“dns_stats.xml”):


```
<group name="dnsstat,">
 <rule id="100010" level="5">
    <field name="integration">dnsstat</field>
    <description>DNS Stats</description>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>
<rule id="100011" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.alerts">LOW-FREQ-SCORES|SUSPECT-FREQ-SCORE</field>
    <description>DNS Stats - Low Frequency Score in Queried Domain</description>
    <mitre>
     <id>T1071</id>
    </mitre>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>
<rule id="100012" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.alerts">YOUR-FIRST-CONTACT</field>
    <description>DNS Stats - Domain Queried for the first time</description>
    <mitre>
     <id>T1071</id>
    </mitre>
    <options>no_full_log</options>
    <group>dnsstat_alert,</group>
  </rule>
<rule id="100013" level="5">
    <if_sid>100010</if_sid>
    <field name="dnsstat.error">\.+</field>
    <description>DNS Stats - Error connecting to API</description>
    <options>no_full_log</options>
    <group>dnsstat_error,</group>
  </rule>
</group>
```


Alerts Examples (domain queried for the first time in your environment):


```
{
  "timestamp":"2021-10-20T07:59:10.937+1100",
  "rule":{
     "level":5,
     "description":"DNS Stats - Domain Queried for the first time",
     "id":"100012",
     "firedtimes":1,
     "mail":false,
     "groups":[
        "dnsstat",
        "dnsstat_alert"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634677150.218702128",
  "decoder":{
     "name":"json"
  },
  "data":{
     "dnsstat":{
        "query":"elconfidencial.com",
        "alerts":[
           "YOUR-FIRST-CONTACT"
        ],
        "category":"ESTABLISHED",
        "freq_score":[
           6.6079,
           6.0942
        ],
        "seen_by_isc":"RDAP",
        "seen_by_web":"Tue, 19 Sep 2000 15:00:50 GMT",
        "seen_by_you":"Tue, 19 Oct 2021 20:59:08 GMT"
     },
     "integration":"dnsstat"
  },
  "location":"dns_stats"
}
```


Alerts Examples (low frequency domain):


```
{
  "timestamp":"2021-10-20T07:58:18.453+1100",
  "rule":{
     "level":5,
     "description":"DNS Stats - Low Frequency Score in Queried Domain",
     "id":"100011",
     "firedtimes":1,
     "mail":false,
     "groups":[
        "dnsstat",
        "dnsstat_alert"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634677098.218295676",
  "decoder":{
     "name":"json"
  },
  "data":{
     "dnsstat":{
        "query":"yt3.ggpht.com",
        "alerts":[
           "LOW-FREQ-SCORES"
        ],
        "category":"ESTABLISHED",
        "freq_score":[
           4.0377,
           3.871
        ],
        "seen_by_isc":"top1m",
        "seen_by_web":"Wed, 16 Jan 2008 18:55:33 GMT",
        "seen_by_you":"Mon, 18 Oct 2021 22:17:34 GMT"
     },
     "integration":"dnsstat"
  },
  "location":"dns_stats"
}
```


ALIENVAULT OTX Integration:

Command and Active Response:


```
<command>
    <name>alienvault_otx</name>
    <executable>otx.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
 <active-response>
   <disabled>no</disabled>
   <level>3</level>
   <command>alienvault_otx</command>
   <location>local</location>
   <rules_group>dnsstat_alert</rules_group>
  </active-response>
```


In the windows agents, we need to create the files “otx.cmd” (active response bin folder):


```
:: Simple script to run Sysinternals Autoruns.
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

"C:\Program Files\PowerShell\7\"pwsh.exe -executionpolicy ByPass -File "c:\Program Files\Sysinternals\otx.ps1"

:Exit
```


NOTE: Powershell 7.x is required for properly parsing the JSON input (JSON alert included by Wazuh manager as part of the active response).

And the file “otx.ps1” (in this example, placed in the sysinternals folder, see [here](https://github.com/juaromu/wazuh)). It can be placed in any folder in the local machine:


```
################################
### Script to check event data on AlienVault OTX IoCs
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# The API Call to OTX will run the parameter passed in the call against existing IoCs
# The API response is filtered out to only get IoCs part of pulses created by the user "AlienVault"
# API Response (relevant fields) in the response converted to JSON and appended to active-responses.log
# An API key to access AlienVault OTX is required (otx.alienvault.com)
##########

# Your OTX API KEY
$otxkey = "Your_API_KEY"
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json 

#Function to Call OTX API with Params and Return Response
function ApiCall($indicator_type, $param) {
  $url = "https://otx.alienvault.com/api/v1/indicators/$indicator_type/$param/general"
  $otx_response = invoke-webrequest -URI $url -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials
  if (($otx_response.StatusCode -eq '200') -And (select-string -pattern '\"username\":\ \"AlienVault\"' -InputObject $otx_response.content))
  {
#Convert Response (JSON) to Array and remove objects
    $otx_response_array = $otx_response | ConvertFrom-Json
    $otx_response_array_trim = $otx_response_array | Select-Object sections,type,base_indicator
#Append Alert to Active Response Log
    echo  $otx_response_array_trim | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
  }
}
#Switch For Rule Group From Alert
$switch_condition = ($INPUT_ARRAY."parameters"."alert"."rule"."groups"[1]).ToString()
switch -Exact ($switch_condition){
#If Rule Group = "new_domain", Extract queried hostname and call the API
#Alert example: {"timestamp":"2021-10-20T05:12:39.783+1100","rule":{"level":5,"description":"DNS Stats - New or Low Frequency Domain Detetcted in Query","id":"100010","firedtimes":2,"mail":false,"groups":["dnsstat","dnsstat_alert"]},"agent":{"id":"034","name":"WIN-7FK8M79Q5R6","ip":"192.168.252.105"},"manager":{"name":"tactical"},"id":"1634667159.125787496","decoder":{"name":"json"},"data":{"dnsstat":{"query":"yt3.ggpht.com","alerts":["LOW-FREQ-SCORES"],"category":"ESTABLISHED","freq_score":[4.0377,3.871],"seen_by_isc":"top1m","seen_by_web":"Wed, 16 Jan 2008 18:55:33 GMT","seen_by_you":"Mon, 18 Oct 2021 22:17:34 GMT"},"integration":"dnsstat"},"location":"dns_stats"}
"dnsstat_alert"
    {
       $indicator_type = 'hostname'
       $hostname = $INPUT_ARRAY."parameters"."alert"."data"."dnsstat"."query"
       ApiCall $indicator_type $hostname  
    break;
    } 
    
}
######################
## Wazuh Manager: Command and AR.
# <command>
#    <name>alienvault_otx</name>
#    <executable>otx.cmd</executable>
#    <timeout_allowed>no</timeout_allowed>
#  </command>
####################
# <active-response>
#   <disabled>no</disabled>
#   <level>3</level>
#   <command>alienvault_otx</command>
#   <location>local</location>
#   <rules_group>dnsstat_alert</rules_group>
#  </active-response>
```


Detection rules (“alienvault_otx_rules.xml”)


```
<group name="alienvault,">
<rule id="91580" level="12">
  <decoded_as>json</decoded_as>
  <field name="sections">\.+</field>
  <field name="type">\.+</field>
  <description>AlienVault OTX -Indicator(s) Found</description>
  <mitre>
   <id>T1036</id>
  </mitre>
  <options>no_full_log</options>
  <group>otx_ioc,</group>
</rule>
</group>
```


Alerts (examples):


```
{
  "timestamp":"2021-10-20T08:38:46.846+1100",
  "rule":{
     "level":12,
     "description":"AlienVault OTX -Indicator(s) Found",
     "id":"91580",
     "mitre":{
        "id":[
           "T1036"
        ],
        "tactic":[
           "Defense Evasion"
        ],
        "technique":[
           "Masquerading"
        ]
     },
     "firedtimes":1,
     "mail":true,
     "groups":[
        "alienvault",
        "otx_ioc"
     ]
  },
  "agent":{
     "id":"034",
     "name":"WIN-7FK8M79Q5R6",
     "ip":"192.168.252.105"
  },
  "manager":{
     "name":"tactical"
  },
  "id":"1634679526.237987400",
  "decoder":{
     "name":"json"
  },
  "data":{
     "sections":[
        "general",
        "geo",
        "url_list",
        "passive_dns",
        "malware",
        "whois",
        "http_scans"
     ],
     "type":"hostname",
     "base_indicator":{
        "id":"2582882147.000000",
        "indicator":"www.mlcrosoft.site",
        "type":"hostname",
        "access_type":"public"
     }
  },
  "location":"active-response\\active-responses.log"
}
```

