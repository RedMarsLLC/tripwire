# Architecture, assessment and implementation phases

## Repository assessment — 2026-10-01

`/Users/jakebrown/repos/tripwire` did not exist. Parent directories contained no applicable AGENTS.md, and no memory_summary.md was present in the checked local memory directory. There was no existing architecture or user work to replace. The host provides macOS 26.5.1, Swift 6.2.3 and Xcode SDK 26.2. The repository path is the authoritative deliverable. Initial staging was reconciled before continuing edits here.

## Boundaries

```text
macOS public APIs / documented read-only utilities
  ↓ independent Collector snapshots + explicit health/scope
TripWireCollectors: source parsing and allowlisted metadata
  ↓
TripWireCore: normalization → SQLite transaction
  ↓
Original baseline + latest observation comparison
  ↓
FindingEngine + conservative CorrelationEngine
  ↓
TripWireCore read model
  ├─ native SwiftUI dashboard and floating overlay
  └─ TripWireTerminal + tripwire commands / JSON
```

`TripWireCore` owns Codable models, SQLite persistence, baseline comparison, detection, correlation, explanations and sequence-gap tracking. `TripWireCollectors` owns host reads and source-specific limitations. `TripWireTerminal` owns pure rendering plus terminal lifecycle. The CLI and GUI consume the same store and collection coordinator. No second detection pipeline exists in the terminal.

Collectors conform to `Collector`. Each returns observations, time, declared scope completeness, absence reliability, state, visibility and detail. A task group permits independent results: errors from one source do not erase or cancel another source's evidence. Fixed utility invocations have time/output bounds and never invoke a shell. A per-store advisory lock prevents two cooperating collector owners. Viewers remain usable while another owner collects.

SQLite transactions atomically save observations, evidence, baseline status, findings and health for each source. Incomplete snapshots cannot infer disappearance. A source must complete its declared initial inventory before establishing its baseline. Socket absence is always unreliable, even after a successful visible-socket inventory. Consumers show last-seen timestamps instead of claiming every historical socket is still open.

The coordinator waits for each round of general inventory collectors before beginning the next round. Continuous monitoring runs the AI open-file collector in a separate bounded loop targeting 2-second intervals; its stop gate rejects any in-flight result after shutdown. One-shot samples include one file snapshot. File-store write failures stop the loop and surface to the coordinator; this loop is not a persistent helper or an exact event stream. Synchronous filesystem/Security framework calls are not isolated into killable workers; a pathological API/filesystem stall can delay subsequent rounds. Stale health makes that visible, but process-level isolation is future work. This is a disclosed reliability limit, not an assurance of uninterrupted coverage.

## Phase status and acceptance gates

### Phase 1 — implemented foundation

- Native dashboard, overlay, terminal, CLI and shared SQLite store.
- Read-only inventory adapters and explicit unavailable sensors.
- Original inventory baselines; creation, metadata change and reliable-scope disappearance evidence.
- Explainable findings, sensor health, local marker canaries, foreground lifecycle, gap persistence, own executable/store metadata.
- Unit/fixture tests, terminal integration checks and local app packaging.

Phase 1 is incomplete in breadth: global registered login/background items, profile inventory, loaded kernel state and several privacy/hardware sources remain unavailable. Their adapters are not invented or simulated.

### Phase 2 — interfaces and loss tracker ready; live providers deferred

Obtain Apple-granted ES entitlement and appropriate signing/provisioning. Build a NOTIFY-only client with separate handling for entitlement, FDA/TCC and privilege errors. Guard message fields by SDK/runtime message version, retain/release messages for asynchronous use, observe sequence counters before reordering, count application-queue drops separately, and start a new continuity epoch at reconnect. No AUTH enforcement in the initial client.

A future Network Extension requires its own signed provider, capabilities, user approval and deployment work. Do not install even an allow-all filter without approval. Distinguish source process audit token from source application attribution. ES local-domain-socket events are not a TCP/UDP flow feed.

For FSEvents, start watching before the initial scan, drain notifications appropriately, preserve drop flags and rescan on coalescing/drop indicators. Event receipt must not be represented as exact file-write attribution.

### Phase 3 — conservative subset implemented

Inventory-change findings and a 30-second persistence/process/network association exist. Correlation requires a referenced absolute executable path, a newly observed process and a matching process instance for a socket observation. It explicitly does not prove launch causality. Individual unsigned, writable-path or new-process observations are not verdicts.

Deferred: statistical normality, destination-frequency models, validated executable hashing/caching, richer ancestry, event-time correlation, protocol-header analysis and investigation workflow/dismissal states. Current findings remain open; counters count stored findings, not confirmed threats.

### Phase 4 — intentionally absent

No process termination, destination blocking, persistence disabling or automatic deletion is available. Future actions require a concrete proposal containing evidence IDs, exact target identity, action, expected effect, rollback, scope and expiry; explicit user approval must precede execution. Revalidate identity at action time (never use PID alone), log the decision/result and offer rollback where technically supported. A detector may only propose, never execute, a response.

## Reliability and evidence invariants

- Unknown is a first-class visibility/status value, never zero or green.
- Confidence is confidence in the observation. Intent is UNKNOWN.
- Observed age does not confer approval or trust.
- A failed read cannot prove deletion; a listening socket cannot prove reachability.
- No fixtures are linked into the live products.
- No coverage percentage without a defensible future definition; this build uses individual sensor states only.
- Store errors surface to the operator. SQLite quick_check verifies structure, not historical authenticity.
