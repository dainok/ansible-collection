"""Filters included in dainok.common collection."""
DOCUMENTATION = """
    name: list_to_dict
    author: Andrea Dainese
    version_added: "0.0.1"
    short_description: return a dict from a list of dicts
    description:
      - from CIDR (10.1.2.0/24) return netmask (255.255.255.0).
    options:
      items:
        description: list of dicts.
        type: list
      key:
        description: the key to be used as index.
        type: list
"""

EXAMPLES = """
# list_to_dict filter example

- name: Print the netmask
  ansible.builtin.debug:
    msg: "{{ '[{"key1": "value1"}, {"key2": "value2"}]' | list_to_dict }}"
"""


def _list_to_dict(self, items: list, key: str) -> dict:
    """Return a dict from a list using key as index."""
    return {item[key]: item for item in items}


class FilterModule(object):
    """Filter plugin."""

    def filters(self):
        """Map filter plugin names to their functions."""
        return {
            "list_to_dict": _list_to_dict,
        }
