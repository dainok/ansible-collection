# cisco_ios_system role

This role configures hostname, domain and DNS servers on Cisco IOS devices.

Prerequisites on Ansible environment:

- `dns_servers` (optional): a list of DNS servers to be used.
- `mgmt_interface`: the interface used to source DNS requests.

Warning:

- If no DNS server is set, the role does not remove configured DNS.
