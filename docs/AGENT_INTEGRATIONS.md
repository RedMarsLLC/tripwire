# Agent activity integrations

TripWire accepts metadata from multiple providers into one private evidence store. This is opt-in, application-reported telemetry, not universal discovery or kernel attestation. Merely installing TripWire cannot observe every agent action. No provider configuration is activated by building. The user separately approved Codex setup; its local CLI feed has now been verified.

## Adapter support and verification

| Adapter | Implemented input | Verification | Live connection |
|---|---|---|---|
| Codex | SessionStart/End, UserPromptSubmit, Pre/PostToolUse, PermissionRequest, Stop, Interrupt | Schema, privacy, lifecycle, deduplication, store tests | Approved, trusted, and verified with a real local CLI tool/lifecycle check; cloud conversation unsupported and local desktop unverified |
| Claude Code | Same supported lifecycle subset plus PostToolUseFailure, StopFailure, SubagentStart/Stop; session_id, agent_id, prompt_id identities | Parser/store tests against documented input shape | Not configured or exercised in a live Claude session |
| Cursor | sessionStart/End, beforeSubmitPrompt, pre/postToolUse, postToolUseFailure, stop; conversation_id and generation_id | Parser tests against documented input shape | Not configured or exercised in a live Cursor session |
| Generic v1 | Contract below for another agent's explicit local instrumentation | Contract/privacy/version tests | Requires a producer; not an automatic adapter for every product |

Run `dist/tripwire agents` for per-identity last reports and counts. The overlay selector separates provider/session/subagent identities. Session and agent IDs are SHA-256 hashed before retention; display uses short prefixes, equality uses full hashes. A Stop from one identity does not imply another agent is idle. Reports lack a reliable delivery heartbeat: current reported state expires after 30 seconds, and silence never proves idle. One session can itself have activity these hooks do not identify; labels describe the reported context only.

Counts are received completion/failure reports in the preceding 60 seconds, not successful actions or total work. PreToolUse does not count a second action. F/P/T categorize tool names, not observed filesystem/process/network effects; A is a request, never an approval outcome. No N is inferred. Timestamps are local receipt time. The UI considers at most 2,048 reports from the last 24 hours plus the last historical report; truncation is LIMITED, never a complete count. This is a bounded recent-identity view, not an inventory of all installed agents. If a hook lacks a subagent identity, it is labeled a session; it cannot distinguish every worker within that session. Missing/error sources remain UNKNOWN. Historical reports do not prove a current connection.

## Generic local contract

Invoke the canonical CLI with argument array `agent-hook --provider generic` and a single UTF-8 JSON object on stdin:

```json
{"schema_version":1,"session_id":"producer-session-id","agent_id":"worker-id","event_id":"unique-event-id","event":"tool.completed","tool_name":"ToolName"}
```

This is a schema example, never a live fixture. Allowed events: `session.started`, `session.ended`, `turn.started`, `tool.started`, `tool.completed`, `tool.failed`, `approval.requested`, `turn.ended`, `turn.interrupted`. Tool events require `tool_name`; optional `tool_use_id` and `turn_id` aid attribution. Stable event_id enables deduplication scoped to provider, session, agent, turn and normalized event. IDs/tool names allow only letters, digits and `._-:/`, maximum 256 UTF-8 bytes. Maximum input is 1 MiB. Unknown keys are discarded, unsupported versions/events rejected. No server or listener is installed.

Native adapters: `agent-hook --provider codex`, `agent-hook --provider claude-code`, `agent-hook --provider cursor`. For compatibility, no provider argument selects Codex. Provider selection comes from invocation, not a trusted assertion about the caller. Any same-user process can forge these reports; no authenticated provenance or complete delivery guarantee is claimed.

Only identifiers/hashes, event name, tool name/category, provider and receipt time persist. No prompts, instructions, tool inputs/outputs, cwd, transcripts, user email, model content, command lines or file contents are retained. Native hooks may transiently put sensitive fields on stdin; TripWire discards them without logging or opening transcript paths. Errors return neutral `{}` and exit zero, never a permission decision, tool rewrite or model instruction. Disconnected/unknown status cannot prove that every callback succeeded.

## Activation boundary

Configuration templates live under `integrations/`, outside auto-loaded provider configuration directories. They are review artifacts, not installed hooks. Replace the quoted `/absolute/path/to/tripwire` placeholder with the executable you built (including `.exe` on Windows); adapt quoting to the provider’s command runner. Template paths are intentionally not executable defaults. Native Windows hook delivery has not been validated. Activation requires approval for the exact user/project config path, command, metadata and scope. Preserve existing config; make a private backup; follow each provider's supported review/trust workflow. Never bypass trust state. No global grants, extensions, login items, daemon or persistent network listener are needed. Disable by removing only the reviewed TripWire entries. Existing evidence remains local until separately removed by the user.

The installed Codex CLI is 0.159.2. Its public app-server proxy could not connect to the existing desktop because the default control socket was absent. Starting a separate server would not attach to that session. The approved Codex hooks subsequently passed trust review and delivered actual events in a fresh local CLI session. That does not attach them to this cloud conversation. Hosted/specialized tools can fall outside Codex hooks. [Codex verified setup and reversal](CODEX_INTEGRATION.md).

## Primary sources checked October 2, 2026

- [Codex hook configuration, trust and event coverage](https://learn.chatgpt.com/docs/hooks)
- [Codex app-server](https://learn.chatgpt.com/docs/app-server)
- [Claude Code hooks, common/subagent fields and locations](https://code.claude.com/docs/en/hooks)
- [Cursor hooks, common schema and events](https://cursor.com/docs/hooks)

## Current versus historical feed presentation

After 30 seconds without a source report the overlay shows **NO RECENT REPORTS** (or **AWAITING REPORTS** when none exist), removes the current action trace, and retains the last-report time. Historical records never keep a zero line alive. A fresh lifecycle event with no completion shows EVENT RECEIVED, not a claim of idle. A positive count is received reports, not total work. This cloud-orchestrated conversation and its locally executed calls have no supported local hook feed; the public desktop control socket was absent and private logs/UI scraping are not used. Local Codex CLI coverage was separately verified.


## Overlay-to-evidence connection

Click the overlay's **AI / ACTION REPORTS** instrument to open **Agent Activity** in the existing dashboard. The selected provider/session/subagent identity carries into the detail view. Each selected identity has its own sampled 60-second trace; the aggregate is never substituted for an individual. Tool/lifecycle descriptions link to the original receipt's evidence ID. The timeline shows up to 100 recent records for the selection, including receipt timestamps and turn identities when provided. These links correlate application reports; they do not attribute host CPU, memory, file changes or network traffic to an agent.

**Source connections** separates default user configuration evidence from report freshness. A bounded, read-only probe checks `~/.codex/hooks.json`, `~/.claude/settings.json` and `~/.cursor/hooks.json` for commands targeting the CLI beside the running app. Only matching event names survive the probe; other config fields/commands are not retained. Files must be regular, non-symlink files no larger than 1 MiB. Missing, unreadable and matching config states are distinct. Project-level, inline and custom-home configurations are outside this probe's scope. Finding entries does not verify enabled state, trust or delivery; received reports are checked separately. This inspection never installs or changes hooks.

This interface measures received action metadata, not machine-wide AI usage, token totals or cost. No recent source report means current activity is unknown. Setup templates remain review artifacts until the user authorizes activation through the provider's supported workflow.

The overlay defaults to **AI APPS / LOCAL CPU** so desktop interaction can contribute its measured local CPU and memory even when action reports are unavailable. Use its selector to switch to **AI / ACTION REPORTS**. These are separate sources: app resource measurements cannot identify a specific prompt, tool action or cloud inference cost. See [local app resource scope](OVERLAY_METRICS.md#ai-desktop-app-resource-scope).
