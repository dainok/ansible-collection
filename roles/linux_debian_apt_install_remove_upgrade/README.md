# linux_debian_apt_install_remove_upgrade role

This role install and eventually upgrades packages on a Debian Linux based box (like Ubuntu or Raspbian).
APT cache can be updated only if older than a configurable value.

Prerequisites on Ansible environment:

* `apt_cache_age` (optional): the maximum age of the cache in seconds. By default it is set to `86400` (1 day).
* `apt_upgrade` (optional): True if the box must be upgraded. By default it is set to `False`.
* `apt_installed_packages` (optional): a list of packages that must be installed.
* `apt_removed_packages` (optional): a list of packages that must be removed.
