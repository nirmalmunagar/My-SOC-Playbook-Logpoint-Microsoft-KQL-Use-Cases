# Logpoint-Query
This repo contains LP query 


## 1. Search command which ran on linux terminal as a root user 
"agentx_unix_full_log"="*nmap*" "device_name"="<host_name>" "/var/log/syslog" | chart count() by agentx_unix_full_log -> this will find nmap command on host

## 2. This query will give top 10 torrent activity user in last X days
"user"=* application=bittorrent | process geoip(destination_address) as country | chart count() as attempt by user, source_address, destination_address, country order by count() desc limit 10  




# KQL Query - MS Defender

## 1. Searching for last X hours of Signins logs based on Account.

```kusto
AADSignInEventsBeta
| where AccountUpn == "delta.nom@xyz.com"  // give UPN name here
| sort by Timestamp asc
| project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType, Country, ConditionalAccessPolicies, State, RiskState, RiskLevelDuringSignIn
```
