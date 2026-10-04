# Brief file-open capture on macOS

A saved tripwire is a policy, not proof that a collector can see every access. The default `ai-open-files` source samples open file and directory handles. A file opened and closed between its checks can leave **no observation and no alert**. Faster polling cannot guarantee detecting that operation. Directory handles are now included, but polling remains incomplete.

## Explicit foreground diagnostic feed

`tripwire file-events` accepts a bounded JSONL stream of Apple's `eslogger open` notifications. It does not launch a privileged process, grant permissions, install a service or modify the target. Only matching enabled rule paths with recognized, same-user AI audit identity associations are retained. No target contents, process arguments, environment values or raw JSON are saved.

This is an optional **diagnostic bridge**, not a stable production Endpoint Security deployment. Apple documents eslogger as a debugging tool; its JSON format is not a promised application API. The bridge accepts schema version 1 and fails closed on unsupported, truncated, oversized or stale records.

1. Use a terminal you explicitly authorize. Apple's eslogger requires administrator authorization and **Full Disk Access for its responsible terminal**. Any grant must be made knowingly by the user in macOS Settings. TripWire does not change privacy settings.
2. Build the CLI, configure the boundary in the app, then run the following from the repository. Keep the pipe in the foreground:

   ```sh
   /usr/bin/sudo /usr/bin/eslogger open | ./dist/tripwire file-events
   ```

   Only `eslogger` runs as root. The TripWire receiver refuses to run as root. If using a different database, append `--db /absolute/path/events.sqlite` to **tripwire**, not eslogger. The Tripwires page provides a quoted command for the actual app and database paths.
3. Inspect **Sensor Status → File-open event bridge**. It must show recent valid input. No recent input is unknown/error, even if it is merely quiet. Starting ordinary monitoring only starts snapshots; it does not start this separate feed.
4. Test using a non-sensitive file in a boundary you explicitly chose. Ask the recognized AI app to open it, then inspect the in-app tripwire alert, path, reported process, association basis and event time. A production finding must come from a real event; test fixtures never populate your store. Do not assume capture is working solely because the terminal process started.
5. Press **Control-C** to stop. Close the pipeline/terminal when finished. The app shows stopped/stale feed status and preserves prior evidence. Review or revoke any terminal permission you no longer want.

The receiver has a separate per-store ownership lock. It can run beside snapshot monitoring; stopping snapshots does not stop the receiver. Both write through the same transactional detection pipeline. Each distinct event can alert; a replay of the same event in a session is deduplicated. Events older than the active rule revision are not treated as a new access after editing that rule. Rule configuration is refreshed every two seconds, so allow that interval before validation.

## Attribution and evidence limits

For an opening process that has already exited, the feed can use the event's OS-reported responsible or immediate-parent audit token. The recognized app must still exist and match its live PID, UID and **PID version**, checked through a task-name port. Process metadata is rechecked to reject PID reuse races. Recognition is an app path/name heuristic, not signature attestation. If identity validation is unavailable, the event cannot produce an AI-associated alert.

An open notification establishes a **reported open**, not bytes actually read/written, intent or authorization. There is no complete audit guarantee. Unrecognized agents, detached responsibility, inherited descriptors, path aliases/hard links, other users and denied identities can remain outside scope. Input over stdin is unauthenticated: a same-user process can forge reports. eslogger suppresses events from its own process group. Sequence gaps are recorded when reported counters permit detection; missing counters never mean zero loss. A quiet stream is not proof of coverage.

Linux still uses `/proc` descriptor snapshots, which can miss brief reads. Windows file-access monitoring is still unavailable. Reliable production deployment needs separately engineered and approved event providers (for example, entitled macOS Endpoint Security, scoped Linux fanotify/audit/eBPF, and an appropriate Windows event provider); this bridge does not implement those providers.

Sources: [Apple eslogger introduction](https://developer-mdn.apple.com/videos/play/wwdc2022/110345/), [Endpoint Security open notification](https://developer.apple.com/documentation/endpointsecurity/es_event_open_t), and the installed `man eslogger` documentation.
