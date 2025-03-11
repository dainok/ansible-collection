"""Filters included in dainok.common collection."""
import ipaddress

DOCUMENTATION = """
    name: cidr_to_netmask
    author: Andrea Dainese
    version_added: "0.0.1"
    short_description: return the netmask from CIDR
    description:
      - from CIDR (10.1.2.0/24) return netmask (255.255.255.0).
    options:
      network:
        description: CIDR specified here is replaced with its netmask.
        type: str
"""

EXAMPLES = """
# cidr_to_netmask filter example

- name: Print the netmask
  ansible.builtin.debug:
    msg: "{{ '10.1.2.0/24' | cidr_to_netmask }}"
"""


def _cidr_to_netmask(self, network: str) -> str:
    """From CIDR (10.1.2.0/24) return netmask (255.255.255.0)."""
    ip = ipaddress.IPv4Network(network)
    return str(ip.netmask)


class FilterModule(object):
    """Filter plugin."""

    def filters(self):
        """Map filter plugin names to their functions."""
        return {
            "cidr_to_netmask": _cidr_to_netmask,
        }
