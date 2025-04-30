# Logpoint-Query
This repo contains LP query 


## 1. Search command which ran on linux terminal as a root user 
"agentx_unix_full_log"="*nmap*" "device_name"="<host_name>" "/var/log/syslog" | chart count() by agentx_unix_full_log -> this will find nmap command on host
