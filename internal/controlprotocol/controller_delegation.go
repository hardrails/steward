package controlprotocol

const (
	// ExecutorCapabilityControllerDelegationV1 means a protocol-4 node can
	// verify a tenant-signed, bounded controller delegation and then accept
	// commands signed by only the delegated online key. Older nodes must not be
	// selected for automated reconciliation.
	ExecutorCapabilityControllerDelegationV1 = "controller-delegation-v1"
)
