# cisco_ios_ntp role

This role configure NTP peers on Cisco IOS devices.

Prerequisites on Ansible environment:

- `ntp_servers`: a list of DNS servers to be used.

Warning:

- Review if the configuration matches your security critierias.

Example:

```yaml
ntp_servers:
  - 0.pool.ntp.org
  - 1.pool.ntp.org
  - 2.pool.ntp.org
  - 3.pool.ntp.org
```
