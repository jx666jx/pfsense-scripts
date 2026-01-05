# pfSense scripts
- **fw-alias-toggle.py** - Toggle the current system's IPv4 address in a pfSense alias. Add the current system if the IP is absent from alias, else remove the current system if IP is present in alias. I wrote this script to move the TouchDesigner machine from VPN egress to DIRECT out when streaming. I didn't want the script to be buried and forgotten inside the TD project.

### required
[pfSense REST API Package](https://github.com/jaredhendrickson13/pfsense-api)

[pfSense REST API Docs](https://pfrest.org/)