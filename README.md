# network monitor
a simple script to constatnly monitor your connectivity to different servers
currently supporting https, http, tcp

## configuration 
### blacklist ip addresses  
you may want to ignore some dns resolutions due to dns poisoning  
`BLACK_LIST_IPS` is where all blacklist ips are listed  
if a domain resolution is in BLACK_LIST_IPS then it is assumed it was not resolved at all  
  
### adding servers and protocols to monitor
the default config file is `CONF_FILE` (servers.yaml)

### example config file:
```yaml
http:
  servers:
    - "google.com"
    - "178.22.122.100"
  timeout: 2
  retries: 1
  count: 3
https:
  servers:
    - "google.com"
icmp:
  servers:
    - "8.8.8.8"
tcp:
  servers:
    - "178.22.122.100:53"
    - "178.22.122.100:443"
    - "178.22.122.100:80"
```
