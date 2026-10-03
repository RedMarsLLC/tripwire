# Security assumptions, privacy and limitations

## Purpose and trust model

TripWire is an observation instrument for an authorized local Mac. Its confidence fields describe evidence quality, not malicious intent. Observed normal state is not trusted state. An absence of findings cannot establish safety. No scanning of nearby or unrelated devices occurs, and no external exposure test is implemented. Listening sockets do not prove Internet reachability: binding, firewall, router/NAT, VPN and other controls matter.

The local OS, frameworks, diagnostic tools and TripWire process are trusted to report honestly. A root attacker, compromised kernel, malicious same-user actor or modified executable may falsify evidence, alter the database or stop monitoring. This build cannot attest the host or itself from outside that trust boundary. On-disk self hashes and database modes detect ordinary sampled changes, not a sufficiently privileged attacker. SQLite quick_check detects structural problems, not forgery, deletion or a complete historical record.

## Read-only boundary

Default live collection reads only declared metadata sources. Writes are limited to TripWire's private evidence state, lock file and user-requested canary marker. No SIP/Secure Boot changes, TCC grants, global permission prompts, root requests, kernel hooks, extensions, filters, launch registrations, automatic process actions, persistence disabling, network setting changes or file deletion are implemented. The GUI starts as a viewer; foreground collection is explicit. The CLI's sample mode stops after one inventory. Application quit/termination is not equivalent to a persistent monitor continuing in the background.

External diagnostic processes use fixed executable paths and argument arrays, not a shell. Locale is fixed, stdin is closed, output is capped at 8 MiB and commands have a default 12-second timeout. Only a diagnostic child created by TripWire is terminated on its own timeout; no monitored/user process is a response target. Filesystem and signing APIs are synchronous and can stall independently of those subprocess bounds; stale heartbeat status exposes delayed coverage. Hard isolation and a persistent independent watchdog are future work.

## Privacy minimization

Not collected: keystrokes, captured audio/video, screenshots, screen contents, packet payloads, document bodies, browser contents/history, full process arguments, environment values, TCC databases, USB/storage serial numbers or file data from arbitrary user-selected locations.

Retained metadata can still be sensitive: executable/persistence paths, process/user IDs, signing identities, network addresses/ports, DNS domains/servers, proxy hosts, device names, configuration summaries, hashes and observation times. It stays on this Mac. JSON output is explicit and should be reviewed before sharing. There is no analytics, uploader, remote server, auto-reporting or network connection initiated by TripWire for telemetry.

Hashing and parsing require reading bytes of specifically scoped application Info.plist manifests and persistence configuration/startup files. Application manifests retain only name, bundle ID, version/build and a hash, alongside bundle/signing metadata; other manifest values and app contents are not retained. Those bytes exist transiently in memory and are never stored as contents. Plist extraction is allowlisted to label, absolute executable target, disabled flag and target signing metadata. ProgramArguments beyond the first target and EnvironmentVariables are never retained. The same bounded no-follow read supplies both the hash and parser, avoiding a second read race. Files over 2 MiB are metadata-only; symlinks retain their destination text without following the target, special files are not read, and detected read races discard content/hash evidence while retaining separately readable metadata with an explicit unknown hash. Own-executable hashing has a separate 128 MiB bound. Paths may themselves contain sensitive names; even metadata is not public data.

The database is not encrypted. New directory/file modes are restrictive; existing parent directory policy is not globally changed. Insecure/symlinked/hard-linked database and sidecar files are rejected without chmod. Read-only viewers do not create an on-disk store or acquire a collector lock. SQLite no-follow open uses a POSIX-resolved parent to support standard macOS /tmp and /var aliases; the database target is never resolved through a symlink. A same-user attacker who can race parent directories or manipulate WAL/state remains inside the stated trust boundary. Do not put the database in a shared writable location. Preserve the local evidence before changing retention; automatic deletion is deliberately absent.

## Observation limitations

- Polling misses brief processes, sockets, attachments and modifications; timestamps are detection times.
- Actual creation/connection time, duration and traffic frequency are not inferred from repeated samples. First/last observation and sample counts are labeled as such.
- Process start time has one-second precision. PID/start/path matching reduces reuse mistakes but is not an ES audit-token identity. Independent socket/process reads can race. Code-signing metadata concerns the sampled path, which may differ from the executable already mapped into a process.
- UDP bound sockets are not TCP listeners and do not establish traffic. ICMP is outside the current socket adapter.
- Protected/restricted reads stay incomplete. Access failure does not uniquely diagnose Full Disk Access/TCC versus Unix permissions or other system restrictions.
- A partial inventory does not establish a complete baseline and never creates removal evidence. It may still record a directly observed change; confidence and limitations travel with that record.
- Baseline confidence can be poisoned if the first observation already contains unwanted state. The baseline is historical reference, not known-good attestation.
- File/plist presence is not evidence of registration, enabled status or execution. No causal claim is made from a matching executable path alone.
- System extension registration state is not runtime health. Installed kernel bundles do not imply loaded code.
- Device registry IDs can change after sleep/reconnect/reboot and are not cryptographic identity. Resource permission is different from activity; activity is different from attributed usage.
- Unavailable ES has unknown losses; no zero-loss claim. Sequence tracking tests do not make the live adapter available.
- Heartbeat staleness uses a 90-second threshold. A longer polling interval can therefore display stale state intentionally; choose an interval below 90 seconds. Generic elapsed gaps cannot distinguish sleep, suspension, termination or clock changes. Unclosed collector session markers additionally expose crashes/restarts even within that threshold. Brief within-interval events can be unobserved.
- Findings are advisory records with no dismissal workflow in this release. Correlation can associate related observations without proving intent or causality. No probability-of-maliciousness score exists.

## Terminal handling

Dynamic terminal values have control characters, ESC/OSC and bidi control characters neutralized. Table cells use predictable ASCII-safe text widths; JSON retains normal escaped data for analysis. Keyboard capture is restricted to commands entered into TripWire's own foreground terminal, never global input monitoring. No ornamental redraw loop or burning-fuse animation runs. Color is not required for any meaning. Terminal restoration is attempted on normal exit, Ctrl-C, EOF, SIGTERM and SIGHUP; no process can restore state after SIGKILL or machine power loss.

## Future deployment approval boundary

Entitlements do not authorize installation by themselves. Installing a persistent helper, ES/system/network extension, registering login startup, granting FDA/capture access or changing networking requires a separate concrete approval. Future response actions require explicit per-action authorization and identity revalidation. This release has no automated response implementation and no network honeypot.

Canary directory checks require private ownership/mode and reject symlinks. Marker creation uses a no-follow directory descriptor with openat and exclusive creation. Persistence inventory does not descend symlinked source directories; it records their link metadata and marks enumeration incomplete.

## Monitoring what an AI agent touches

The product goal is to connect a concrete action to a target, a responsible process/agent, the evidence supporting that attribution and the rule that made it worth reviewing. Current snapshots can establish some changes, but cannot reconstruct every touch or label a change agent-caused merely because an AI session or CPU spike occurred nearby. Security Watch exposes those limits alongside the available inventories. Existing apps in the first baseline are not implicitly approved; a newly observed app is not automatically unwanted.

AI open-file snapshots now retain regular-file path/open-mode and holding-process metadata for recognized AI apps and observed same-user descendants. They do not open or read target files; even sensitive-location detection uses path metadata only. Short-lived or detached activity may be missed, and mode does not establish actual I/O. Metadata paths can be sensitive and remain in the private local store.

The next collection boundary is a metadata-only, NOTIFY-only Endpoint Security adapter for version-supported process exec/fork/exit, file open/create/modified-close/rename/unlink and kernel extension load/unload events. An open notification is not proof of a particular payload being read; a load notification does not identify who originally created the bundle. Actor identity must use the OS process instance/audit-token identity and verified ancestry. Delegation through an unrelated helper, preexisting process or service must remain unattributed without an explicit evidence link. Self-reported hooks remain supporting context, not an independent OS audit source. Sequence loss, queue overflow, unsupported event types, reconnection and startup gaps must be recorded before any completeness claim.

This adapter is **not implemented or deployed**. Apple requires a granted [Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client); the [client API](https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:)) also requires user TCC/Full Disk Access approval and appropriate privileges/signing. The existing ad-hoc app is not a deployable entitled provider. No grants, root helper, system extension or persistent installation were added. OS-backed network flow attribution is a separate source; neither file notifications nor a matching time window proves network causation.

After reliable collection, a separate review policy should distinguish authorized workspaces and actions from sensitive locations, new installed software, persistence, extension changes and new listening services. Evidence must retain the target, operation, observed actor or explicit unknown, rule reason, before/after state when available, and source limitations. User approval applies to the exact reviewed evidence; no age-based trust, implicit approval of an initial baseline, automatic blocking or remediation.
