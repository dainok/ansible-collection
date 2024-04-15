import ipaddress

class FilterModule(object):
	"""Ansible filter."""

	def cidr_to_netmask(self, network: str) -> str:
		"""From CIDR (10.1.2.0/24) return network (255.255.255.0)"""
		ip = ipaddress.IPv4Network(network)
		return str(ip.netmask)
	
	def cidr_to_network(self, network: str) -> str:
		"""From CIDR (10.1.2.0/24) return network (10.1.2.0)"""
		ip = ipaddress.IPv4Network(network)
		return str(ip.network_address)

	def cidr_to_prefixlen(self, network: str) -> int:
		"""From CIDR (10.1.2.0/24) return prefix length (24)"""
		ip = ipaddress.IPv4Network(network)
		return ip.prefixlen

	def cidr_to_wildcard(self, network: str) -> str:
		"""From CIDR (10.1.2.0/24) return network (0.0.0.255)"""
		ip = ipaddress.IPv4Network(network)
		return str(ip.hostmask)

	def list_to_dict(self, items: list, key:str) -> dict:
		"""Return a dict from a list using key as index."""
		return {item[key]: item for item in items}

	def filters(self):
		"""Invoked function. Keys define how filters are called."""
		return {
			"cidr_to_netmask": self.cidr_to_netmask,
			"cidr_to_network": self.cidr_to_network,
			"cidr_to_prefixlen": self.cidr_to_prefixlen,
			"cidr_to_wildcard": self.cidr_to_wildcard,
			"list_to_dict": self.list_to_dict,
		}
