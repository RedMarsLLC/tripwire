# Codex local action reports — development verification

This records a development-machine check. Cloning or building TripWire does not activate hooks for another user. Start from `integrations/codex/hooks.template.json`, replace the placeholder executable path and follow Codex’s supported trust review.

On October 2, 2026, after explicit approval, the eight prepared entries were installed in `~/.codex/hooks.json` and trusted through the installed Codex CLI 0.159.2 `/hooks` interface. The file did not previously exist, so no prior file required backup. No existing hooks were replaced; no security feature, permission, credential, model or trust bypass was changed. Codex displayed all eight as active.

A fresh `--no-daemon` local CLI session ran a harmless `/usr/bin/true` integration check. Real SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop and SessionEnd receipts reached the shared TripWire store. Exactly one tool completion was received; its tool name was Bash. No raw input/output/prompt/transcript fields were retained. PermissionRequest and Interrupt parsing are tested, but those event deliveries were not forced during the live check. The temporary validation CLI was then closed; only the approved hook configuration remains for future supported sessions.

**Coverage boundary:** this verifies locally orchestrated Codex CLI activity, not this cloud-orchestrated conversation. OpenAI documents that local command hooks are unsupported with cloud orchestration, even when execution is local. Desktop sessions with local orchestration were not independently verified. A public app-server proxy probe found no control socket for attaching to the current desktop session. No new background daemon was installed and no private session logs were read. Manual CLI `!` shell mode did not produce tool receipts in this check; the agent's actual shell-tool invocation did.

The initial review session did not produce all event types after trusting; the real tool test used a fresh session. Existing sessions must not be described as attached without actual receipts. Use `dist/tripwire agents` to inspect recent identities, receipt time and lifecycle. Current state expires to UNKNOWN after 30 seconds without a report. A receipt is not a heartbeat, complete activity coverage, or proof of tool success.

## Exact activation and reversal

- Config: `~/.codex/hooks.json`, private mode 0600.
- Command for each selected event: `"/absolute/path/to/tripwire" agent-hook` (default provider: Codex).
- Events: SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse, PermissionRequest, Stop, Interrupt; timeout 2 seconds.
- Retention: `~/Library/Application Support/TripWire/events.sqlite` and its private WAL/SHM sidecars; timestamps, event/tool names and hashed identities only.
- Input may transiently include Codex's standard sensitive fields; adapter discards them, never opens transcript paths, and emits neutral `{}`. No permission decision or tool rewrite.
- To disable: use Codex `/hooks` to disable the eight TripWire entries, or remove only the matching entries from this file. Do not overwrite other hooks. Historical TripWire evidence stays local.
- Changing a hook definition requires Codex's supported review/trust step again. Never bypass that gate.

[All provider contracts and limitations](AGENT_INTEGRATIONS.md). Local validation metadata is in ignored `validation/activity-final/`; it is not shipped as live fixtures.

Primary references: [Codex hooks, tool coverage, trust and cloud limitations](https://learn.chatgpt.com/docs/hooks), [public app-server](https://learn.chatgpt.com/docs/app-server).
