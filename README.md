# pfSense scripts (for TouchDesigner)
I wrote these scripts to move a TouchDesigner machine from VPN egress to 
DIRECT out when streaming. pfSense egress is handled via an IPs membership in an alias (group). These script provide output to CLI or TouchDesigner operators. I didn't want the scripts to be buried and forgotten inside the TD project.

- **fw_alias_toggle.py** - Toggle the current system's IPv4 address in a pfSense alias. Add the current system if the IP is absent from the alias, else remove the current system if IP is present in the alias. 

- **pfs_vpn_pub_check.py** - Compare the pfSense WAN interface IP with the public IP reported by ifconfig.io. Returns "direct" if they match, or "vpn" if they differ. Handles DHCP-assigned WAN IPs by querying the runtime status endpoint.

### required
[pfSense REST API Package](https://github.com/jaredhendrickson13/pfsense-api)

[pfSense REST API Docs](https://pfrest.org/)