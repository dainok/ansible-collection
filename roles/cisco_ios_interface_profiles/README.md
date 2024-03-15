# cisco_ios_port_profile role

This role configure ports based on profiles.

Prerequisites on Ansible environment:

- `interfaces`: a list of dict defining interface and profile name (example {"interface": "Ethernet0/0", "profile": "access_port"}).
- `interface_profiles`: a list of dict defining each profile with associated configuration lines (example {"disabled_port_profile": ["shutdown"]}).

Example:

```yaml
interface_profiles:
  access_port_profile:
    - no cdp enable
    - no lldp receive
    - no lldp transmit
    - spanning-tree bpduguard enable
    - spanning-tree portfast edge
    - switchport mode access
    - switchport nonegotiate
  trunk_port_profile:
    - no cdp enable
    - no lldp receive
    - no lldp transmit
    - spanning-tree bpduguard enable
    - spanning-tree portfast edge trunk
    - switchport trunk encapsulation dot1q
    - switchport mode trunk
    - switchport nonegotiate
  isl_port_profile:
    - ip dhcp snooping trust
    - switchport trunk encapsulation dot1q
    - switchport mode trunk
    - switchport nonegotiate
    - udld port aggressive
  disabled_port_profile:
    - shutdown
interfaces:
  - interface: GigabitEthernet1/0
    profile: access_port_profile
  - interface: GigabitEthernet1/1
    profile: trunk_port_profile
  - interface: GigabitEthernet1/2
    profile: isl_port_profile
```
