package controlprotocol

const (
	// ExecutorCapabilityAuthorizedEffectsV1 is advertised by every node-scoped
	// Executor uplink protocol whose local admission and Gateway path enforce
	// request-bound authorized effects. It does not change the delivery or
	// report wire shape, so protocols 2, 3, and 4 can advertise it.
	ExecutorCapabilityAuthorizedEffectsV1 = "authorized-effects-v1"
	// ExecutorCapabilityContextLockedEffectsV1 means admission, immutable
	// runtime topology, Gateway, and connector receipts enforce grant-scoped
	// response-history bindings on exact effect permits.
	ExecutorCapabilityContextLockedEffectsV1 = "context-locked-effects-v1"
)
