# 🛡️ Daily SOC Queries: Logpoint & Microsoft KQL

A curated collection of real-world queries from my day-to-day activities as a Security Engineer. This repository includes practical examples and use cases using: 
- 🔍 **Logpoint SIEM**
- 📊 **Microsoft Defender XDR (Kusto Query Language - KQL)**




# KQL Query - MS Defender

## 1. Searching for last X hours of Signins logs based on Account.

```kusto
AADSignInEventsBeta
| where AccountUpn == "delta.nom@xyz.com"  // give UPN name here
| sort by Timestamp asc
| project Timestamp, AccountUpn, DeviceName, IPAddress, LogonType, Country, ConditionalAccessPolicies, State, RiskState, RiskLevelDuringSignIn
```


## 2. Detect Brute Force or Password Spray
This query help to detect Password spary, Brute force, Suspicious Ip making repeated failed attempts
```kusto
AADSignInEventsBeta
| where AccountUpn == "delta.nom@xyz.com"
| where ErrorCode != 0  \\ Filter failed login attempt
| summarize FailedAttempts = count() by bin(Timestamp, 1h), IPAddress, City, State // bin(Timestamp,1h) is Time based bucket grouped by IPAddress. count failure per number of IP/hour
| sort by Timestamp asc
```

## 3. Sign-ins Over Time (Timeline View)
This query help to detect Unusual spike in activity, Access outside business hours and automated sign-in Attempts.
```kusto
AADSignInEventsBeta
| where AccountUpn == "delta.nom@xyz.com"
| summarize SignInCount = count() by bin(Timestamp, 1h) //Groups events into 1-hour time bucket and counts the number of sign-ins per hour
| sort by Timestamp
```

## 4. Find out all users who received mail from attacker address.
This query will list all user in timeframe who received mail from malicious sender address.
```kusto
EmailEvents
| where SenderFromAddress == "xyz@mail.com"
| summarize EmailCount = count() by RecipientEmailAddress, Subject
| order by EmailCount desc
```

---

# Logpoint-Query

## 1. Search command which ran on linux terminal as a root user 
```plaintext
"agentx_unix_full_log"="*nmap*" "device_name"="<host_name>" "/var/log/syslog" | chart count() by agentx_unix_full_log -> this will find nmap command on host
```

## 2. This query will give top 10 torrent activity user in last X days
```plaintext
"user"=* application=bittorrent | process geoip(destination_address) as country | chart count() as attempt by user, source_address, destination_address, country order by count() desc limit 10  
```



## 👨‍💻 About Me

I'm a Security Engineer working in a SOC environment, focused on detection engineering, threat intel correlation, and SOAR automation.
