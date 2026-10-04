# Risk control and local review

The Overview console summarizes **open findings by current classification**. Critical is red, High orange, Medium amber, Low cyan, and Unassessed muted purple. Labels accompany colors. Click a module to filter the investigation queue; use Open / Reviewed and search to inspect the evidence, reason, association and source limitations.

Risk is review priority, not observation confidence or a verdict of malicious intent. Existing severity maps to an initial suggestion: elevated → High, notice → Medium, informational → Low. Unknown confidence starts Unassessed. Critical is available for an explicit user correction; TripWire does not invent a new automatic critical detection rule. Low is not a safety claim. Counts are unknown if the store cannot be read.

**All levels** removes the risk filter; it does not clear findings. **Clear queue (count)…** separately moves the displayed open findings to **Reviewed → Cleared** after showing a confirmation. It respects the current level and search, preserves risk levels and all evidence, and makes no claim that activity was safe, expected, or falsely flagged. New findings arriving after the confirmation opens stay open. Clearing is atomic: if a selected finding has been reviewed elsewhere, nothing is cleared and the queue must be refreshed. Future alerts remain enabled. To undo a clear, select the finding in Reviewed, change its status to Open, and save with a reason.

To correct a finding, select a risk level, choose **Open**, **Cleared**, **Expected activity**, or **False positive**, and give a reason (1–500 characters). Saved corrections immediately update summaries. Reviewed findings remain available in their queue and history. A false positive marks the user's interpretation; it does not delete the underlying observation.

Corrections are append-only records in the private `finding_reviews` table. The original finding, suggested classification, detection reason, linked evidence and baseline are retained. The latest committed correction determines the current view. Concurrent stale edits are rejected instead of overwriting another correction; reload and inspect it before trying again. Reviews apply only to that finding, never as a rule exemption or suppression of future alerts. Existing databases acquire the new table when first opened for an authorized write; read-only old stores remain readable.

```sh
tripwire review EXACT-FINDING-ID --json
tripwire review EXACT-FINDING-ID --level low --status expected \
  --reason 'This matches the task I authorized' --expected-review none
```

For later corrections, use the `assessment.latestReview.id` returned by the read command instead of `none`. CLI `view --json` includes full-store risk counts and assessments for displayed findings. The portable queue is limited to the latest 1,000 findings and says so when truncated; totals cover all findings. The macOS and Qt dashboards use the same storage and classification model.

For a confirmed bulk clear, `tripwire review --clear-queue` accepts a JSON array on stdin containing explicit `findingID` and `expectedReviewID` pairs (`null` for an unreviewed finding). Input is bounded to 1 MiB and 10,000 distinct findings. There is no implicit clear-all command.
