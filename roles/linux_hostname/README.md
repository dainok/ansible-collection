# linux_hostname role

This role configure the local hostname and domain name. If current hostname is different, then a reboot of the host is initiated.

Prerequisites on Ansible environment:

* `ansible_host`: the IP address of the host (i.e. `192.168.0.1`).
* `inventory_hostname`: the FQDN of the host (i.e. `raspberrypi.example.com`).
* `inventory_hostname_short`: the hostname of the host (i.e. `raspberrypi`).

The above configuration can be set in the inventory file:

~~~ini
[all]
raspberrypi.example.com ansible_host=192.168.0.1 ansible_user=root ansible_unprivuser=pi ansible_unprivpassword=raspberry
~~~
