# cisco_ios_vlan role

This role configures VLANs on Cisco IOS devices.

Prerequisites on Ansible environment:

- `vlans`: a list of dict describing VLANs ({"id": 20, "name": "SERVER"})
- `mtu` (optional): the  MTU used (default is 1500)
