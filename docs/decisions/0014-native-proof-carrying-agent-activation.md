# 0014. Build native proof-carrying agent activation

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

Steward already verifies signed agent capsules, imports exact OCI archives,
admits workloads through Executor, dispatches tenant-authorized service tasks,
and records signed evidence. Operators still have to assemble those controls
into a long sequence of commands before an agent performs useful work. That
gap makes secure deployment harder to operate and harder to audit.

Hosted agent platforms reduce this friction with a choose, configure, test,
activate, and monitor journey. Their cloud accounts, hosted credential custody,
automatic updates, and vendor-controlled evidence do not fit Steward's
air-gapped or customer-controlled trust boundary. A general workflow engine
would also introduce a second execution and policy surface inside the control
plane.

## Decision

Build a thin, standard-library-only activation coordinator around Steward's
existing security contracts:

- a publisher-signed agent release describes the outcome, embeds the exact
  capsule, binds the offline OCI archive, and defines one closed deterministic
  canary;
- an unsigned activation plan binds the exact local inputs and timeouts but
  grants no authority;
- a resumable node-local runner verifies and imports the image, admits and
  starts the workload, then pauses for a task permit derived from the real
  Executor admission response;
- a portable activation proof binds the signed inputs, exact canary, terminal
  result, and signed evidence needed for independent offline verification.

The default flow keeps the tenant task-signing key off the node. It emits a
bounded signing challenge after admission and resumes only when the matching
task bundle is supplied. An explicit local-signing option may trade stronger
key custody for a one-command activation, but it does not change permit
validation or widen authority.

**Tradeoff:** Steward owns a small amount of orchestration code and a public
release format. In return, an operator can activate useful agent work without
trusting a hosted control plane, and an auditor can verify the result without
network access. The first release supports one closed Hermes workspace-audit
canary and node-local transport; broader recipes remain unsupported until they
have equally precise contracts.

**Rejected:** A hosted catalog, visual workflow builder, generic DAG engine,
arbitrary hooks, and automatic A/B winner selection. They expand Steward's
authority and attack surface without improving tenant isolation or offline
proof. Also rejected is pre-signing a guessed task permit: the permit must bind
the actual admission response, including the runtime reference and effective
policy and route-policy digests.

## Consequences

Agent releases are descriptive and publisher-signed, but never grant tenant,
node, connector, egress, inference, or task authority. Site policy, instance
intent, Executor admission, and tenant task permits remain authoritative.

Activation is a fixed state machine rather than a programmable workflow.
Changed immutable inputs cannot resume an existing activation. Ambiguous
external effects become a sticky `action_required` state and are inspected
before any retry. The coordinator never mints replacement authority, silently
destroys a failed workload, or treats missing evidence as success.

Controller-driven end-to-end activation remains deferred. The current control
uplink reports a runtime reference and status, but not the complete admission
projection required to issue a task permit. Revisit remote activation only
after that projection has a separately reviewed signed or independently
verifiable transport contract.
