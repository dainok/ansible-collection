# linux_systemd_enable_disable role

This role enable and disable services using systemd.

This is usually the last role to be executed.

Prerequisites on Ansible environment:

* `systemd_enabled` (optional): the list of services to be enabled.
* `systemd_disabled` (optional): the list of services to be disabled and unmaked.
* `systemd_masked` (optional): the list of services to be disabled and masked.
