# cisco_ios_tiemzone role

This role configures tiemzone and daylight saving time.

Prerequisites on Ansible environment:

- `timezone` (optional, default is GMT): the timezone in Cisco IOS format.
- `summertime` (optional): the summertime configuration in Cisco IOS format.

Example:

```yaml
timezone: CET 1 0
summertime: CEST recurring last Sun Mar 2:00 last Sun Oct 3:00
```
