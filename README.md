# HAFNIUM

## CVE-2021-26855
> CVE-2021-26855 is a server-side request forgery (SSRF) vulnerability in Exchange which allowed the attacker to send arbitrary HTTP requests and authenticate as the Exchange server.

## CVE-2021-26857
> CVE-2021-26857 is an insecure deserialization vulnerability in the Unified Messaging service. Insecure deserialization is where untrusted user-controllable data is deserialized by a program. Exploiting this vulnerability gave HAFNIUM the ability to run code as SYSTEM on the Exchange server. This requires administrator permission or another vulnerability to exploit.

## CVE-2021-26858
> CVE-2021-26858 is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.

## CVE-2021-27065
> CVE-2021-27065 is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.


## Indicators

### IP Addresses
Malicious IP addresses Here

### Web Shell Hashes
A list of hashes Here

### Web Shell Paths
A list of common paths Here

### Web Shell Names
Webshells can be found Here

### User-Agents
A list of user agents found here