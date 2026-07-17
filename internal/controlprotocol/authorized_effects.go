package controlprotocol

const (
	// ExecutorCapabilityAuthorizedEffectsV1 is advertised by every node-scoped
	// Executor uplink protocol whose local admission and Gateway path enforce
	// request-bound authorized effects. It does not change the delivery or
	// report wire shape, so protocols 2, 3, and 4 can advertise it.
	ExecutorCapabilityAuthorizedEffectsV1 = "authorized-effects-v1"
)
