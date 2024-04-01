# linux_debian_openssh role

This role install and configures OpenSSH server, sftp server and client.

Prerequisites on Ansible environment:

* `ssh_root_login` (optional): it refers to `PermitRootLogin` and can be `yes`, `prohibit-password`, `without-password`, `forced-commands-only`, or `no`. By default it is set to `prohibit-password`.
* `ssh_use_dns` (optional): it refers to `UseDNS`. By default it is set to `no`.
* `ssh_client_alive_interval` (optional): it refers to `ClientAliveInterval`. By default it is set to `14400`.
* `ssh_client_alive_count` (optional):  it refers to `ClientAliveCountMax`. By default it is set to `5`.
