# Your tripwires

Open **Tripwires** in the dashboard to define boundaries for current-account or AI-associated activity. Choose a name, an absolute target path and a boundary type:

- **File:** an in-scope process is observed holding that exact file open, or a matching reported file operation from the separately authorized macOS event bridge.
- **Folder:** the same observation at the folder path or inside any of its subfolders.
- **Application:** an in-scope open file inside a macOS `.app` bundle (or at the selected executable), or the selected application's executable observed running under the selected account scope (with recognized AI ancestry for AI-only rules). On Linux and Windows, select the executable file rather than an app's display name or shortcut.

Use **Choose…** or enter the path directly. Saving never opens the target, changes its permissions or starts collection. Enable **Start monitoring** for repeated observations. Each rule shows the relevant source status; enabled configuration is not a guarantee of live coverage. Windows file-access monitoring remains unavailable, while its process snapshots can support scoped application observations.

The matching rule produces an elevated finding titled **Tripwire triggered: NAME**, with the observed path, process, association basis, detection time, why it matched, and a link to the exact evidence. The dashboard displays a dismissible banner and the overlay links to recorded findings/alerts. Dismissing clears all currently queued banners for that app session; evidence stays in the database. Identical repeated activity remains in Findings without reopening the banner until there has been a 30-second quiet period. A different process/action, path or rule revision can alert immediately. This does not change risk classifications, disable rules or stop collection. No OS notification permission is required. Alerts are in-app, so a closed application cannot display them.

Rules are evaluated against newly collected rows, including unchanged baseline rows. Existing baseline approval never exempts a configured boundary. Saving a rule does not reclassify stale inventory as a fresh access. There is one alert per rule revision, observed process instance and path/event class, retained across collector restarts. A new process instance can alert again; each distinct event-feed operation can also alert. Editing or re-enabling a rule starts a new revision; deleting or disabling a rule stops future matches while preserving existing findings and configuration history.

Brief opens/reads can be entirely missed by snapshots. The dashboard now shows this setup gap explicitly. See [foreground event capture and its authorization requirements](FILE_EVENTS.md).

Findings support [risk corrections and Open / Expected activity / False positive review status](RISK_REVIEW.md). A review never disables future rule matches.

## What an alert establishes

File snapshots establish that a process held a file or directory descriptor at observation time. Its mode expresses capability, not a proven read, write, modification or disclosure. Descriptors can be inherited. Application matches use observed process paths, identities and bounded parent chains; process start times and matching account identities constrain ancestry. Name/path recognition can be spoofed, and observed ancestry does not prove an AI instruction or exact launch causality. No process arguments, environment values or target contents are collected.

Partial snapshots can still produce alerts for actual observed rows, with their source limitations retained. Missing or unavailable evidence never becomes an absence claim. Polling can miss brief operations, detached launches, unrecognized agents, other users and protected processes. A failed sensor must be investigated in **Sensor Status / Checks**.

Paths are compared lexically, with directory-component boundaries. `/private/keys` does not match `/private/keys-backup`. Windows drive paths are matched case-insensitively; Unix paths preserve case. TripWire does not resolve symlink aliases or equate hard links. A rule may miss access under a different path spelling. Filesystem roots are allowed but can generate many alerts. Configuration supports up to 128 rules per evidence store.

Tripwires are alerts, not an access-control sandbox: they do not deny access, kill processes, uninstall applications or change system security settings.

## CLI and storage

```sh
tripwire tripwires list --json
tripwire tripwires save --name 'Private project' --path /absolute/private/project --kind folder
tripwire tripwires save --name 'Sensitive app' --path /Applications/Private.app --kind application
tripwire tripwires disable RULE-UUID
tripwire tripwires enable RULE-UUID
tripwire tripwires delete RULE-UUID
```

Use `save --id RULE-UUID` to edit, and `--disabled` to save a disabled rule. All commands accept `--db`. Windows uses an absolute drive path and the executable's `.exe` path for application rules. Invalid configuration is rejected before creating a store. Listing is read-only, including on first launch.

Rules and deduplication markers live in the private SQLite metadata store; configuration changes are recorded as configuration events, not detection findings. All running collectors pick up changes on subsequent snapshots without a restart. The existing schema and original baseline remain intact. The Qt app invokes the same bounded local CLI commands as the terminal; it has no second rule engine, listener or web server.

## Account scope and access explanation

Choose **Any process under my account** to alert on observed access by your apps, command-line tools and unrecognized AI helpers. Choose **AI-associated processes only** to require a recognized AI identity/ancestry. Existing rules preserve AI-only behavior; newly created rules default to the current-account scope. Editing retains the rule ID and audit trail. CLI: `tripwire tripwires save --name NAME --path /absolute/path --kind folder --scope current-user`.

Findings show the observed operation, executable/PID, account, parent and OS-reported responsible process when available. A command-line label is an inference from the observed executable, never proof of who typed or launched it. Mouse, keyboard, physical user vs automation and intent remain **unknown**; TripWire does not collect input events, arguments or contents.

The optional macOS feed accepts open, write, modified-close, rename and unlink reports; unmodified closes do not create a second alert. Rename source/destination paths are retained only if inside a boundary. An open is not proof that bytes were read. Subscriptions cannot be authenticated from stdin and source loss/limitations remain visible. Linux offers snapshots; Windows file activity remains unavailable.
