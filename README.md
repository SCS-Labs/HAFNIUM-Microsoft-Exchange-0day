# HAFNIUM

## CVE-2021-26855
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
> CVE-2021-26855 is a server-side request forgery (SSRF) vulnerability in Exchange which allowed the attacker to send arbitrary HTTP requests and authenticate as the Exchange server.

## CVE-2021-26857
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26857
> CVE-2021-26857 is an insecure deserialization vulnerability in the Unified Messaging service. Insecure deserialization is where untrusted user-controllable data is deserialized by a program. Exploiting this vulnerability gave HAFNIUM the ability to run code as SYSTEM on the Exchange server. This requires administrator permission or another vulnerability to exploit.

## CVE-2021-26858
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26858
> CVE-2021-26858 is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.

## CVE-2021-27065
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065
> CVE-2021-27065 is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.


## Indicators

### IP Addresses
Malicious IP addresses [Here](/indicators/ip-addresses)

### Web Shell Hashes
A list of hashes [Here](/indicators/hashes)

### Web Shell Paths
A list of common paths [Here](/indicators/webshell_paths)

### Web Shell Names
Webshells can be found [Here](/indicators/webshell_names)

### User-Agents
A list of user agents found [Here](/indicators/useragents)


## Timeline




## Tool Detections

## Post Exploitation

## Mitigations and Detections

## Vendor Security Research

### Volexity
### Mandiant Managed Defense
### Red Canary
### Cisco Talos
### Nextron Systems
### Recon Infosec

## Government or Agency Security Research

### CISA

### CERT Latvia



## Tweets

## Cool Resources
- [CheckMyOWA](https://checkmyowa.unit221b.com)
> **What is it?** We set up this site to aid victim notification based on lists of compromised Exchange servers with Outlook Web Access(OWA) enabled, which were obtained from perpetrators of this mass breach event. This includes affected IPs/domains, as well as whether the actors in this first wave of attacks successfully loaded a shell. The problem of notifying such a large number of victims is compounded by the lack of legal framework or even available WHOIS data to determine the identity of the owner of an IP or domain to notify them of a serious problem on their property. This website stands as an imperfect approach to a global problem.


# To-Do
- Build Complete Timeline
- Post Exploitation Section
- Tweets Section
- Mitigations and Detections Section
- Vendor Security Research
- Government or Agency Security Research


