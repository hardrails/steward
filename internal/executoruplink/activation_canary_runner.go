package executoruplink

import (
	"context"
	"sync"

	"github.com/hardrails/steward/internal/controlprotocol"
)

type activationCanaryJob struct {
	ctx        context.Context
	credential string
	delivery   controlprotocol.ExecutorDeliveryV4
	command    command
}

// activationCanaryRunner runs one remote canary independently from the polling
// loop. Serial execution is deliberate: while a canary is active, the node
// omits the canary capability from polls. The controller then leaves its lease
// untouched while it can still lease containment and reconciliation commands.
//
// There is no in-memory queue. If a nonconforming controller returns another
// canary in the same poll, the DeliveryStore's accepted phase remains its
// durable pending record and the current lease may be redelivered later.
type activationCanaryRunner struct {
	mu     sync.Mutex
	active *activationCanaryJob
}

func newActivationCanaryRunner(enabled bool) *activationCanaryRunner {
	if !enabled {
		return nil
	}
	return &activationCanaryRunner{}
}

func (runner *activationCanaryRunner) available() bool {
	if runner == nil {
		return false
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.active == nil
}

// owns reports only an exact delivery generation. It prevents a duplicated
// member in one poll response from re-entering DeliveryStore.AcceptV4 while
// the same generation is already scheduled.
func (runner *activationCanaryRunner) owns(
	delivery controlprotocol.ExecutorDeliveryV4,
) bool {
	if runner == nil {
		return false
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return sameActivationCanaryJob(runner.active, delivery)
}

// schedule returns true only when this caller must start the worker. A false
// accepted result means another canary is active; the caller leaves the
// delivery durably accepted for a later lease redelivery instead of inventing
// a terminal command failure or retaining tenant work in a shared FIFO.
func (runner *activationCanaryRunner) schedule(
	job activationCanaryJob,
) (start, accepted bool) {
	if runner == nil {
		return false, false
	}
	job.command.Payload = append([]byte(nil), job.command.Payload...)
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.active == nil {
		runner.active = cloneActivationCanaryJob(job)
		return true, true
	}
	if sameActivationCanaryJob(runner.active, job.delivery) {
		return false, true
	}
	return false, false
}

func (runner *activationCanaryRunner) current(
	deliveryID string,
) (activationCanaryJob, bool) {
	if runner == nil {
		return activationCanaryJob{}, false
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.active == nil || runner.active.delivery.DeliveryID != deliveryID {
		return activationCanaryJob{}, false
	}
	return *cloneActivationCanaryJob(*runner.active), true
}

func (runner *activationCanaryRunner) complete(
	deliveryID string,
) (activationCanaryJob, bool) {
	if runner == nil {
		return activationCanaryJob{}, false
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.active == nil || runner.active.delivery.DeliveryID != deliveryID {
		return activationCanaryJob{}, false
	}
	runner.active = nil
	return activationCanaryJob{}, false
}

func (runner *activationCanaryRunner) stop(deliveryID string) {
	if runner == nil {
		return
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.active == nil || runner.active.delivery.DeliveryID != deliveryID {
		return
	}
	runner.active = nil
}

func sameActivationCanaryJob(
	job *activationCanaryJob,
	delivery controlprotocol.ExecutorDeliveryV4,
) bool {
	return job != nil &&
		job.delivery.DeliveryID == delivery.DeliveryID &&
		job.delivery.DeliveryGeneration == delivery.DeliveryGeneration &&
		job.delivery.CommandID == delivery.CommandID &&
		job.delivery.CommandDigest == delivery.CommandDigest
}

func cloneActivationCanaryJob(job activationCanaryJob) *activationCanaryJob {
	clone := job
	clone.command.Payload = append([]byte(nil), job.command.Payload...)
	return &clone
}

func (p *Poller) startActivationCanary(
	ctx context.Context,
	credential string,
	delivery controlprotocol.ExecutorDeliveryV4,
	cmd command,
) error {
	if p.canaryRunner == nil {
		return p.rejectDeliveryV4(
			ctx,
			credential,
			delivery,
			"activation_canary_unavailable",
			"this node does not have the closed activation canary runtime",
			nil,
		)
	}
	start, accepted := p.canaryRunner.schedule(activationCanaryJob{
		ctx:        ctx,
		credential: credential,
		delivery:   delivery,
		command:    cmd,
	})
	if !accepted {
		p.logger.Warn(
			"defer activation canary while another canary is active",
			"delivery_id",
			delivery.DeliveryID,
		)
		return nil
	}
	if start {
		go p.runActivationCanaries(delivery.DeliveryID)
	}
	return nil
}

func (p *Poller) runActivationCanaries(deliveryID string) {
	job, ok := p.canaryRunner.current(deliveryID)
	if !ok {
		p.logger.Error(
			"activation canary worker lost its scheduled delivery",
			"delivery_id",
			deliveryID,
		)
		return
	}
	if job.ctx.Err() != nil {
		p.canaryRunner.stop(deliveryID)
		return
	}
	p.executeActivationCanary(job)
	_, _ = p.canaryRunner.complete(deliveryID)
}

func (p *Poller) executeActivationCanary(job activationCanaryJob) {
	if err := p.deliveryState.MarkExecuting(job.delivery.DeliveryID); err != nil {
		// No external effect has started. The durable accepted delivery remains
		// eligible for a later controller lease instead of being misreported as
		// an execution failure.
		p.logger.Error(
			"persist executing activation canary delivery",
			"delivery_id",
			job.delivery.DeliveryID,
			"error",
			err,
		)
		return
	}
	local := p.executeActivationCanarySafely(job.ctx, job.command)
	report := makeReportV4(job.delivery, local, job.command.Kind)
	if err := p.deliveryState.MarkTerminalV4(report); err != nil {
		p.logger.Error(
			"persist terminal activation canary delivery",
			"delivery_id",
			job.delivery.DeliveryID,
			"error",
			err,
		)
		p.persistActivationCanaryOutcomeUnknown(
			job.ctx,
			job.credential,
			job.delivery,
		)
		return
	}
	if err := p.sendReportV4(job.ctx, job.credential, report); err != nil {
		// The durable terminal report is retried with the current credential at
		// the start of the next poll. A report transport failure must not stop
		// lifecycle polling or reopen the completed canary.
		p.logger.Warn(
			"report terminal activation canary delivery",
			"delivery_id",
			job.delivery.DeliveryID,
			"error",
			err,
		)
	}
}

func (p *Poller) executeActivationCanarySafely(
	ctx context.Context,
	cmd command,
) (result report) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = report{
				CommandID:       cmd.CommandID,
				Status:          controlprotocol.ExecutorStatusFailed,
				ReportedStatus:  "failed",
				ClaimGeneration: cmd.ClaimGeneration,
				Result: map[string]any{
					"error": "activation canary executor panicked",
				},
				effectUncertain: true,
			}
		}
	}()
	return p.dispatcher.execute(ctx, cmd)
}

func (p *Poller) persistActivationCanaryOutcomeUnknown(
	ctx context.Context,
	credential string,
	delivery controlprotocol.ExecutorDeliveryV4,
) {
	rejected := controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         delivery.DeliveryID,
		DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID:          delivery.CommandID,
		CommandDigest:      delivery.CommandDigest,
		Status:             controlprotocol.ExecutorStatusRejected,
		ReportedStatus:     "failed",
		ErrorCode:          "activation_canary_persistence_failed",
		Result: controlprotocol.ExecutorReportResultV4{
			Error: "activation canary terminal state could not be persisted",
		},
	}
	terminal, err := p.deliveryState.RejectV4(delivery, rejected)
	if err != nil {
		p.logger.Error(
			"persist ambiguous activation canary recovery",
			"delivery_id",
			delivery.DeliveryID,
			"error",
			err,
		)
		return
	}
	if terminal == nil {
		return
	}
	if err := p.sendReportV4(ctx, credential, *terminal); err != nil {
		p.logger.Warn(
			"report ambiguous activation canary recovery",
			"delivery_id",
			delivery.DeliveryID,
			"error",
			err,
		)
	}
}
