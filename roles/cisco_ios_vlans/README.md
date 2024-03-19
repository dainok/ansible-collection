# cisco_ios_vlan role

This role configures VLANs on Cisco IOS devices.

Prerequisites on Ansible environment:

- `vlans`: a list of dict describing VLANs ({"id": 20, "name": "SERVER"})

Example:

```yaml
mtu: 1500
vlans:
  - id: 20
    name: SERVER
  - id: 30
    name: CLIENT
```
