"""Filters included in dainok.common collection."""
import ipaddress

DOCUMENTATION = """
    name: cidr_to_wildcard
    author: Andrea Dainese
    version_added: "0.0.1"
    short_description: return wildcard from CIDR
    description:
      - from CIDR (10.1.2.0/24) return wildcard (0.0.0.255).
    options:
      network:
        description: CIDR specified here is replaced with its wildcard.
        type: str
"""

EXAMPLES = """
# cidr_to_wildcard filter example

- name: Print the wildcard
  ansible.builtin.debug:
    msg: "{{ '10.1.2.0/24' | cidr_to_wildcard }}"
"""


def _cidr_to_wildcard(self, network: str) -> str:
    """From CIDR (10.1.2.0/24) return wildcard (0.0.0.255)."""
    ip = ipaddress.IPv4Network(network)
    return str(ip.hostmask)


class FilterModule(object):
    """Filter plugin."""

    def filters(self):
        """Map filter plugin names to their functions."""
        return {
            "cidr_to_wildcard": _cidr_to_wildcard,
        }
