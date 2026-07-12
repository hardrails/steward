package gateway

import (
	"net/netip"
	"testing"
)

func TestDefaultEgressAddressPolicyDeniesSpecialPurposeRegistries(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
	}{
		// IANA IPv4 Special-Purpose Address Registry.
		{name: "this network", address: "0.0.0.1"},
		{name: "private 10", address: "10.1.2.3"},
		{name: "shared CGNAT and Tailscale", address: "100.100.100.100"},
		{name: "loopback", address: "127.0.0.1"},
		{name: "link local", address: "169.254.1.1"},
		{name: "private 172", address: "172.20.1.1"},
		{name: "IPv4 service continuity", address: "192.0.0.1"},
		{name: "IPv4 dummy", address: "192.0.0.8"},
		{name: "PCP anycast v4", address: "192.0.0.9"},
		{name: "TURN anycast v4", address: "192.0.0.10"},
		{name: "NAT64 discovery v4", address: "192.0.0.170"},
		{name: "TEST-NET-1", address: "192.0.2.1"},
		{name: "AS112 v4", address: "192.31.196.1"},
		{name: "AMT v4", address: "192.52.193.1"},
		{name: "deprecated 6to4 relay", address: "192.88.99.1"},
		{name: "6a44 relay anycast", address: "192.88.99.2"},
		{name: "private 192", address: "192.168.1.1"},
		{name: "direct delegation AS112 v4", address: "192.175.48.1"},
		{name: "benchmarking v4", address: "198.18.0.1"},
		{name: "TEST-NET-2", address: "198.51.100.1"},
		{name: "TEST-NET-3", address: "203.0.113.1"},
		{name: "reserved v4", address: "240.0.0.1"},
		{name: "limited broadcast", address: "255.255.255.255"},

		// IANA IPv6 Special-Purpose Address Registry.
		{name: "loopback v6", address: "::1"},
		{name: "IPv4-mapped v6", address: "::ffff:8.8.8.8"},
		{name: "IPv4 IPv6 translation", address: "64:ff9b::1"},
		{name: "local-use IPv4 IPv6 translation", address: "64:ff9b:1::1"},
		{name: "discard-only", address: "100::1"},
		{name: "dummy v6", address: "100:0:0:1::1"},
		{name: "IETF protocol assignments v6", address: "2001:100::1"},
		{name: "TEREDO", address: "2001::1"},
		{name: "PCP anycast v6", address: "2001:1::1"},
		{name: "TURN anycast v6", address: "2001:1::2"},
		{name: "DNS-SD anycast v6", address: "2001:1::3"},
		{name: "benchmarking v6", address: "2001:2::1"},
		{name: "AMT v6", address: "2001:3::1"},
		{name: "AS112 v6", address: "2001:4:112::1"},
		{name: "deprecated ORCHID", address: "2001:10::1"},
		{name: "ORCHIDv2", address: "2001:20::1"},
		{name: "drone remote ID tags", address: "2001:30::1"},
		{name: "documentation v6", address: "2001:db8::1"},
		{name: "6to4", address: "2002::1"},
		{name: "direct delegation AS112 v6", address: "2620:4f:8000::1"},
		{name: "documentation v6 3fff", address: "3fff::1"},
		{name: "SRv6 SIDs", address: "5f00::1"},
		{name: "unique local", address: "fd00::1"},
		{name: "link local v6", address: "fe80::1"},
		{name: "unallocated v6 unicast", address: "4000::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if addressAllowed(netip.MustParseAddr(test.address), nil) {
				t.Fatalf("default policy allowed %s", test.address)
			}
		})
	}

	for _, address := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !addressAllowed(netip.MustParseAddr(address), nil) {
			t.Errorf("default policy denied public address %s", address)
		}
	}
	if addressAllowed(netip.MustParseAddr("::ffff:8.8.8.8"), nil) {
		t.Fatal("default policy allowed the IPv4-mapped special-purpose range")
	}
}

func TestExplicitEgressCIDRsMayAllowSpecialPurposeUnicast(t *testing.T) {
	for _, test := range []struct {
		address string
		prefix  string
	}{
		{address: "0.0.0.1", prefix: "0.0.0.0/8"},
		{address: "10.1.2.3", prefix: "10.0.0.0/8"},
		{address: "100.100.100.100", prefix: "100.64.0.0/10"},
		{address: "127.0.0.1", prefix: "127.0.0.0/8"},
		{address: "169.254.1.1", prefix: "169.254.0.0/16"},
		{address: "192.0.2.1", prefix: "192.0.2.0/24"},
		{address: "198.18.0.1", prefix: "198.18.0.0/15"},
		{address: "64:ff9b::1", prefix: "64:ff9b::/96"},
		{address: "100::1", prefix: "100::/64"},
		{address: "2001:1::1", prefix: "2001::/23"},
		{address: "2001:db8::1", prefix: "2001:db8::/32"},
		{address: "5f00::1", prefix: "5f00::/16"},
		{address: "fd00::1", prefix: "fc00::/7"},
		{address: "fe80::1", prefix: "fe80::/10"},
		{address: "::ffff:8.8.8.8", prefix: "8.8.8.8/32"},
	} {
		if !addressAllowed(netip.MustParseAddr(test.address), []netip.Prefix{netip.MustParsePrefix(test.prefix)}) {
			t.Errorf("explicit CIDR %s did not allow %s", test.prefix, test.address)
		}
	}
}

func TestExplicitEgressCIDRsCannotAllowInvalidDestinations(t *testing.T) {
	for _, test := range []struct {
		name    string
		address netip.Addr
		prefix  netip.Prefix
	}{
		{name: "invalid", address: netip.Addr{}, prefix: netip.MustParsePrefix("0.0.0.0/0")},
		{name: "unspecified v4", address: netip.MustParseAddr("0.0.0.0"), prefix: netip.MustParsePrefix("0.0.0.0/0")},
		{name: "unspecified v6", address: netip.MustParseAddr("::"), prefix: netip.MustParsePrefix("::/0")},
		{name: "multicast v4", address: netip.MustParseAddr("224.0.0.1"), prefix: netip.MustParsePrefix("0.0.0.0/0")},
		{name: "limited broadcast", address: netip.MustParseAddr("255.255.255.255"), prefix: netip.MustParsePrefix("0.0.0.0/0")},
		{name: "multicast v6", address: netip.MustParseAddr("ff02::1"), prefix: netip.MustParsePrefix("::/0")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if addressAllowed(test.address, []netip.Prefix{test.prefix}) {
				t.Fatal("fundamentally invalid destination was explicitly allowed")
			}
		})
	}
}
