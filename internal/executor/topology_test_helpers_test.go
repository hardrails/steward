package executor

// testNetworkSpec projects one representative Docker IPAM allocation onto a
// Steward network identity. Production never derives addresses from tenant text;
// Docker selects a collision-free subnet and InspectNetwork performs this same
// projection from the daemon's observed allocation.
func testNetworkSpec(tenantID, instanceID string, generation uint64) NetworkSpec {
	spec, err := networkSpecFromIPAM(
		NetworkSpecFor(tenantID, instanceID, generation),
		"172.30.0.0/29",
		"",
	)
	if err != nil {
		panic(err)
	}
	return spec
}
