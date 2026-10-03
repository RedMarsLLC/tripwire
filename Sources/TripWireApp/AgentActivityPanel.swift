import SwiftUI
import TripWireCore

struct AgentActivityPanel: View {
    @EnvironmentObject var model: DashboardModel
    var identity: String?

    var body: some View {
        let now = Date(), activity = model.agents.selecting(identity)
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(identity == nil ? "AI activity and sources" : "Agent session activity").font(.title2.bold())
                Spacer()
                if identity != nil { Button("All agents and sources") { model.route = .agents(nil) } }
            }
            Text("Provider reports → local evidence store → overlay. Counts describe received tool completions and failures; they do not measure tokens, cost, or all AI usage on the machine.")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                Text(activity.feedTitle(at: now)).font(.headline.monospaced()).foregroundStyle(.yellow)
                Text(activity.hasRecentReport(at: now) ? activity.lifecycle(at: now) : "Current work or idle state is unknown. Open an instrumented local agent session to receive new reports.")
                Text(activity.lastEventText(at: now)).font(.caption.monospaced())
                if let error = activity.error { Text(error).foregroundStyle(.orange) }
                if activity.truncated { Text("The recent report window is truncated. Counts and session lists may be incomplete.").foregroundStyle(.orange) }
            }.padding().frame(maxWidth: .infinity, alignment: .leading).background(panel).clipShape(RoundedRectangle(cornerRadius: 8))

            if identity == nil {
                Text("Source connections").font(.title3.bold())
                ForEach(model.agentSources) { source in
                    let received = model.agents.forProvider(source.provider)
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(source.provider.name).font(.headline)
                            Spacer()
                            Text(received.feedTitle(at: now)).font(.caption.monospaced()).foregroundStyle(accent)
                        }
                        Text(source.explanation).font(.callout)
                        if let last = received.latestEvent {
                            Text("Last received: \(TimeText.iso(last.timestamp)) · \(last.actionDescription)").font(.caption.monospaced())
                            Button("Inspect latest \(source.provider.name) session") { model.route = .agents(last.identity) }
                        }
                        Text(source.provider == .codex
                             ? "Local CLI hooks are supported. This cloud-orchestrated conversation is not covered; an open desktop app does not prove a reporting session."
                             : source.provider == .generic
                             ? "The producer must explicitly send metadata through the generic v1 adapter."
                             : "Use the provider’s supported hook setup and trust workflow. A parser being available does not enable delivery.")
                            .font(.caption).foregroundStyle(.secondary)
                    }.padding().frame(maxWidth: .infinity, alignment: .leading).background(panel).clipShape(RoundedRectangle(cornerRadius: 8))
                }
                Text("Observed sessions").font(.title3.bold())
                ForEach(activity.identities, id: \.identity) { agent in
                    Button { model.route = .agents(agent.identity) } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(agent.label).font(.headline.monospaced())
                                Text(agent.actionDescription).font(.callout)
                            }
                            Spacer()
                            Text(agent.state(at: now)).font(.caption.monospaced())
                            Image(systemName: "arrow.up.right")
                        }.padding().frame(maxWidth: .infinity, alignment: .leading).background(panel).clipShape(RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
            } else if let agent = activity.latestEvent {
                Text(agent.label).font(.headline.monospaced())
                Text("Session identity: \(agent.identity)").font(.caption.monospaced()).textSelection(.enabled)
            }

            Text("Received event timeline").font(.title3.bold())
            let reports = activity.reports.sorted { $0.timestamp > $1.timestamp }
            if reports.isEmpty {
                Text(activity.error == nil ? "No reports in the recent window for this selection. Silence does not establish inactivity." : "The timeline is unavailable until evidence can be read.").foregroundStyle(.secondary)
                if let last = activity.latestEvent {
                    Button("Inspect last historical report") { model.route = .event(last.id) }
                }
            }
            LazyVStack(alignment: .leading, spacing: 8) {
                ForEach(Array(reports.prefix(100))) { report in
                    Button { model.route = .event(report.id) } label: {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(report.actionDescription).font(.headline)
                                Text(report.label + (report.turnHash.map { " · turn " + $0.prefix(8) } ?? "")).font(.caption.monospaced())
                                Text("\(report.event) · Inspect source evidence →").font(.caption).foregroundStyle(accent)
                            }
                            Spacer()
                            Text(TimeText.iso(report.timestamp)).font(.caption.monospaced())
                        }.padding().frame(maxWidth: .infinity, alignment: .leading).background(panel).clipShape(RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
            }
            if reports.count > 100 { Text("Showing the newest 100 of \(reports.count) loaded reports. Select a session to narrow the timeline.").font(.caption) }
            Text("Correlation uses provider, hashed session/subagent/turn identities, and evidence IDs. These application reports can be omitted or forged by same-user processes; they do not establish host effects or malicious intent. A permission request does not mean permission was granted. Current reported state expires after 30 seconds without an event. Host CPU/RAM measurements are not attributed to AI.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Only event/tool metadata and hashed identities are retained. Prompts, arguments, outputs, transcripts and document contents are not stored. Setup instructions: docs/AGENT_INTEGRATIONS.md.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
