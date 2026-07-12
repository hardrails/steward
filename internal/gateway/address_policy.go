package gateway

import "net/netip"

// specialPurposePrefixes pins the IANA IPv4 and IPv6 Special-Purpose Address
// Registries last updated 2025-10-09. The broad entries deliberately cover
// their more-specific registrations: an operator must name an allowed_cidrs
// exception before Steward will connect to any special-purpose address.
//
// Registry sources:
//   - https://www.iana.org/assignments/iana-ipv4-special-registry/
//   - https://www.iana.org/assignments/iana-ipv6-special-registry/
var specialPurposePrefixes = []netip.Prefix{
	// IPv4.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),

	// IPv6. Loopback, unspecified, and IPv4-mapped addresses are handled
	// before this table; an explicit IPv4 CIDR may authorize a mapped address.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

var currentlyAllocatedIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
var limitedIPv4Broadcast = netip.MustParseAddr("255.255.255.255")

func addressAllowed(address netip.Addr, prefixes []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	mappedIPv4 := address.Is4In6()
	address = address.Unmap()
	// These destinations cannot be made safe by an operator CIDR exception.
	// Private, loopback, link-local, and other special-purpose unicast ranges
	// can be explicitly allowed for a known deployment topology.
	if address.IsUnspecified() || address.IsMulticast() || address == limitedIPv4Broadcast {
		return false
	}
	if len(prefixes) > 0 {
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	if mappedIPv4 {
		return false
	}
	if !address.IsGlobalUnicast() || address.Is6() && !currentlyAllocatedIPv6GlobalUnicast.Contains(address) {
		return false
	}
	for _, prefix := range specialPurposePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
