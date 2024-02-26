# Unofficial python api wrapper for [noip.com](https://www.noip.com/) targeting users with free accounts. Everything is included in a single Python file, making integration into your project effortless.

# The API supports the following actions:

- Checking the state of your active noip hostnames and confirming those expiring in 7 days. You can create a cron script to confirm expiring hostnames automatically
- Adding new hostnames
- Deleting a hostname, and
- Updating a hostname

# Dependecies

- requests
- sys
- re
- ipaddress

# Usage

\*Initialize client

noip = noIP(email, password) 

You can then access noip attributes

## checkMyHostnames

Retrieves active noip hostnames and updates those expiring in 7 days

Example:
```
noip.checkMyHostnames()
```
## addNewHostname

Creates the given hostname in the given domain using one of the 4 record types: ipv4 (A), ipv6 (AAA), cname, and web redirect. The default domain and record type are 'ddns.net' and 'ipv4', respectively.
```
Takes the following arguments:
hostname: A prefix of a domain name e.g. 'api' without 'ddns.net'.

domain: The host to attach the new hostname to e.g. 'ddns.net'. The default domain is 'ddns.net' Check the noip website for available free hosts.

record_type: The record type to use when creating a new hostname.
            Valid options are: 'ipv4', 'ipv6', 'cname', and 'web-redirect'. 'ipv4' is used as the default if none is specified. Record type is also infered from 'ipv4', 'ipv6', 'cname', and 'web-redirect-url' options. E.g., if 'ipv6' is provided, the 'ipv6' record_type is automatically used.
            
            {ipv4}: 'ipv4' address required if this record type is selected, current ip is used as the default.
            {ipv6}: both 'ipv4' and 'ipv6' addresses are required when this record type is selected, current ip is used as the default.
            {cname}: requires the 'cname' e.g. 'example.domain.com'.
            {web-redirect}: requires the url or ipv4 address where the url will redirect.

ipv4: The ipv4 adddress. Current address is used when not provided. Required for both 'ipv4'(A) and 'ipv6'(AAAA) record types.
ipv6: The ipv6 address. Required for the 'ipv6'(AAAA) record type.
cname: The cname e.g. 'example.domain.com'. Required for the 'cname' record type
web_redirect_url: The full web_redirect_url with protocol e.g. 'https://example.com' or 'http://10.67.1.1:8080/web'. Required for 'web-redirect' record type.

Usage examples:
noip = noip(email, pass)
noip.addNewHostname('home-camera') #creates home-camera.ddns.net using current ipv4 address.
noip.addNewHostname('home-camera', record-type='ipv6', ipv6='2001:0db8:85a3:0000:0000:8a2e:0370:7334' ipv4='30.5.7.8') #creates ipv6 record type
noip.addNewHostname('home-camera', ipv6='2001:0db8:85a3:0000:0000:8a2e:0370:7334') #creates ipv6 record type. The current ipv4 address is used.
noip.addNewHostname('home-camera', ipv4='30.5.7.8') #creates home-camera.ddns.net using the provided ipv4 address, useful for remote servers.
noip.addNewHostname('home-camera', record-type=cname cname="example.com")
noip.addNewHostname('home-camera', record-type=web-redirect web_redirect_url="https://example.com") #the web redirect record is created with the mask URL option unchecked.

Server response is printed if hostname creation fails e.g. when the provided hostname already exists.
```
## deleteHostname

Deletes the given hostname from your noip account. Prints error message if deletion fails e.g. the provided hostname is not in your account.

Example:
```
noip.deleteHostname('example.ddns.net')
```
## updateHostname

Updates the given hostname with the given ip addresses. If no ip address is given, the current ip will be used.

Currently supports hostnames with record types 'ipv4(A) and 'ipv6'(AAAA) only.

Examples:
```
noip.updateHostname('example.ddns.net') #updates the given 'hostname' with current system ip address

noip.updateHostname('example.ddns.net', ipv4='123.67.6.8') #updates the given 'hostname' with the given ipv4 address

noip.updateHostname('example.ddns.net', ipv6='2001:0db8:85a3:0000:0000:8a2e:0370:7334') #updates the given 'hostname' with the given ipv6 address
```
