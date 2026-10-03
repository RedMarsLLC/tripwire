import SwiftUI
import TripWireCore

struct SecurityWatchPanel: View {
    @EnvironmentObject var model: DashboardModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Review what changed on this Mac").font(.title2.bold())
            Text("TripWire flags observed changes so you can decide whether they match what you authorized. The initial baseline records what was present; it does not certify that existing software is wanted or safe.")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                Label("AI action attribution remains limited", systemImage: "exclamationmark.shield").font(.headline).foregroundStyle(.orange)
                Text("This build cannot show everything an AI agent touches. File Activity associates observed open files with recognized apps and sampled child processes. It does not prove an AI instruction, actual reads/writes, or who installed an app or changed a setting.")
                Button("Inspect the missing OS event collector →") { model.route = .coverage(.sensor("endpoint-security")) }
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))

            area("Applications", explanation: "New, changed or missing .app bundles in /Applications and your Applications folder. Bundle/version/signing metadata only; other locations and command-line packages are outside scope.", sources: ["applications"], destination: .inventory(.applications, .all))
            area("Ports and connections", explanation: "Visible TCP listeners and socket-owning processes; UDP bindings are listed separately. Brief sockets can be missed. Remote reachability and the agent that caused a port to open remain unknown.", sources: ["network"], destination: .inventory(.network, .all))
            area("Kernel and system extensions", explanation: "Installed kernel bundles in /Library/Extensions and registered system extensions. Creating a bundle elsewhere, loading kernel code and runtime health are not observed by these inventories.", sources: ["kernel-bundles", "extensions"], destination: .inventory(.system, .all))
            area("Startup items and security settings", explanation: "Changes to scoped launch files, helpers, shell startup metadata and selected security/network settings. This is not a complete inventory of every persistence mechanism.", sources: ["persistence", "configuration"], destination: .inventory(.persistence, .all))
            area("AI file activity", explanation: "Open-file snapshots show paths held by recognized AI apps and observed descendants, with process identity and read/write capability. Sensitive credential, startup and extension locations get review findings. Brief opens, actual I/O and detached agents may be missed; the OS event audit remains unavailable.", sources: ["ai-open-files", "endpoint-security"], destination: .files)

            HStack {
                Text("Findings to investigate").font(.title3.bold())
                Spacer()
                Button("All findings →") { model.route = .findings(nil) }
            }
            Text("Open a finding for what changed, why it was flagged, before/after evidence and the attribution limits. These are recorded findings, not confirmed incidents.").foregroundStyle(.secondary)
            if model.view == nil {
                Text("Evidence is unavailable. Finding counts are unknown.").foregroundStyle(.orange)
            } else if model.view?.findings.isEmpty == true {
                Text("No findings recorded. This does not establish that no unwanted activity occurred.").foregroundStyle(.secondary)
            }
            ForEach(Array((model.view?.findings ?? []).prefix(6))) { finding in
                FindingSummary(finding: finding) { model.route = .findings(finding.id) }
            }
        }
    }

    private func area(_ title: String, explanation: String, sources: [String], destination: DashboardRoute) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title).font(.headline).foregroundStyle(accent)
                Spacer()
                Button("Inspect →") { model.route = destination }.accessibilityLabel("Inspect \(title)")
            }
            Text(explanation).font(.callout)
            ForEach(sources, id: \.self) { id in
                if let sensor = model.sensors.first(where: { $0.id == id }) {
                    Button { model.route = .coverage(.sensor(id)) } label: {
                        Label("\(sensor.descriptor.name): \(model.readError == nil ? SensorPresentation(sensor).title : "Evidence unavailable") →", systemImage: "viewfinder")
                    }.font(.caption)
                }
            }
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
    }
}
