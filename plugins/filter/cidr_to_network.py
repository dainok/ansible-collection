"""Filters included in dainok.common collection."""
import ipaddress

DOCUMENTATION = """
    name: cidr_to_network
    author: Andrea Dainese
    version_added: "0.0.1"
    short_description: return network from CIDR
    description:
      - from CIDR (10.1.2.0/24) return network (10.1.2.).
    options:
      network:
        description: CIDR specified here is replaced with its network.
        type: str
"""

EXAMPLES = """
# cidr_to_network filter example

- name: Print the network
  ansible.builtin.debug:
    msg: "{{ '10.1.2.0/24' | cidr_to_network }}"
"""


def _cidr_to_network(self, network: str) -> str:
    """From CIDR (10.1.2.0/24) return network (10.1.2.0)."""
    ip = ipaddress.IPv4Network(network)
    return str(ip.network_address)


class FilterModule(object):
    """Filter plugin."""

    def filters(self):
        """Map filter plugin names to their functions."""
        return {
            "cidr_to_network": _cidr_to_network,
        }
