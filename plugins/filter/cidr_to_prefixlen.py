"""Filters included in dainok.common collection."""
import ipaddress

DOCUMENTATION = """
    name: cidr_to_prefixlen
    author: Andrea Dainese
    version_added: "0.0.1"
    short_description: return prefixlen from CIDR
    description:
      - from CIDR (10.1.2.0/24) return prefix length (24).
    options:
      network:
        description: CIDR specified here is replaced with its prefixlen.
        type: str
"""

EXAMPLES = """
# cidr_to_prefixlen filter example

- name: Print the prefixlen
  ansible.builtin.debug:
    msg: "{{ '10.1.2.0/24' | cidr_to_netmask }}"
"""


def _cidr_to_prefixlen(self, network: str) -> int:
    """From CIDR (10.1.2.0/24) return prefix length (24)."""
    ip = ipaddress.IPv4Network(network)
    return ip.prefixlen


class FilterModule(object):
    """Filter plugin."""

    def filters(self):
        """Map filter plugin names to their functions."""
        return {
            "cidr_to_prefixlen": _cidr_to_prefixlen,
        }
