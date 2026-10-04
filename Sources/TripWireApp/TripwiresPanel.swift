import SwiftUI
import AppKit
import TripWireCore

struct TripwiresPanel: View {
    @EnvironmentObject var model: DashboardModel
    @State private var draft = TripwireRule(name: "", path: "", kind: .folder, scope: .currentUser)
    @State private var editing = false
    private var rules: [TripwireRule] { model.view?.tripwires ?? [] }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Set the boundaries.").font(.system(size: 28, weight: .bold, design: .monospaced))
                    Text("Choose protected files, folders and applications. Include all activity under your account or only recognized AI-associated processes. A supported observation that matches a tripwire raises an alert with the evidence.").foregroundStyle(CyberTheme.muted).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("+ Lay a tripwire") { draft = TripwireRule(name: "", path: "", kind: .folder, scope: .currentUser); editing = true }
            }
            HStack(spacing: 12) {
                MetricButton("Enabled boundaries", model.view == nil ? "—" : String(rules.filter(\.enabled).count), note: "Configuration is not live coverage", icon: "scope") { editing = true }
                MetricButton("Recorded alerts", model.view == nil ? "—" : String(model.tripwireAlerts.count), note: "Inspect the rule and supporting evidence", icon: "bolt.shield") { model.route = .tripwireAlerts }
            }
            FileEventSetup()
            Label("Alerting only · No access blocking · Choose the account scope per rule", systemImage: "info.circle").foregroundStyle(accent)
            Text("File rules use file/directory handle snapshots on macOS and Linux. The separately authorized macOS foreground event bridge can also capture brief opens. Application rules also inspect sampled process identities. Brief access, detached launches, aliases and unrecognized agents may be missed. An open file does not prove a read or write. Windows file-access monitoring remains unavailable.").font(.callout).foregroundStyle(CyberTheme.muted)
            if let error = model.configurationError { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
            if editing { editor }
            if rules.isEmpty && !editing {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Your boundaries start here.").font(.title3.bold()).foregroundStyle(accent)
                    Text("Add a private project folder, a specific key file, or an application. Nothing is selected or monitored by this configuration until you add a rule and run the available checks.")
                    Button("Create your first tripwire") { editing = true }
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading).cyberPanel()
            }
            ForEach(rules) { rule in ruleCard(rule) }
            HStack { Text("REDMARS LLC / 2026"); Spacer(); Text("MIT LICENSE · Copyright & license notice must travel with copies") }
                .font(.system(size: 10, design: .monospaced)).foregroundStyle(CyberTheme.muted).padding(.top, 10)
        }
    }
    private var editor: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(rules.contains { $0.id == draft.id } ? "EDIT TRIPWIRE" : "NEW TRIPWIRE").font(.headline).foregroundStyle(CyberTheme.pink)
            TextField("Name, e.g. Private credentials", text: $draft.name).textFieldStyle(.roundedBorder).accessibilityLabel("Tripwire name")
            Picker("Who triggers this?", selection: Binding(get: { draft.effectiveScope }, set: { draft.scope = $0 })) { ForEach(TripwireScope.allCases) { Text($0.label).tag($0) } }
            Picker("Boundary", selection: $draft.kind) { ForEach(TripwireKind.allCases) { Text($0.label).tag($0) } }.pickerStyle(.segmented)
            HStack {
                TextField("Absolute path", text: $draft.path).textFieldStyle(.roundedBorder).accessibilityLabel("Tripwire target path")
                Button("Choose…") { choose() }
            }
            Text(draft.scopeDescription).font(.callout).foregroundStyle(CyberTheme.muted)
            Toggle("Enabled for future observations", isOn: $draft.enabled).toggleStyle(.switch)
            Text("Saving does not open the target or start monitoring. Editing or re-enabling a rule begins a new alert cycle on the next matching snapshot.").font(.caption).foregroundStyle(CyberTheme.muted)
            HStack {
                Button("Save tripwire") { if model.saveTripwire(draft) { editing = false; draft = TripwireRule(name: "", path: "", kind: .folder, scope: .currentUser) } }
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || draft.path.isEmpty)
                Button("Cancel") { editing = false; model.configurationError = nil }
            }
        }.padding(20).cyberPanel()
    }
    private func ruleCard(_ rule: TripwireRule) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: rule.kind == .application ? "app.badge" : rule.kind == .folder ? "folder.badge.person.crop" : "doc.badge.gearshape").foregroundStyle(accent)
                Text(rule.name).font(.headline); Spacer()
                Text(rule.enabled ? "ENABLED" : "DISABLED").font(.caption.bold()).foregroundStyle(rule.enabled ? accent : CyberTheme.muted)
            }
            Text(rule.path).font(.body.monospaced()).textSelection(.enabled)
            Text(coverage(rule)).foregroundStyle(.orange).font(.callout)
            Text(rule.scopeDescription).font(.caption).foregroundStyle(CyberTheme.muted)
            HStack {
                Button("Edit") { draft = rule; editing = true }
                Button(rule.enabled ? "Disable" : "Enable") { var changed = rule; changed.enabled.toggle(); model.saveTripwire(changed) }
                Button("Delete", role: .destructive) { model.deleteTripwire(rule) }
                Spacer()
                if let finding = model.tripwireAlerts.first(where: { $0.ruleID == "user-tripwire:" + rule.id }) {
                    Button("Inspect alert ↗") { model.route = .findings(finding.id) }
                }
            }
        }.padding(20).cyberPanel()
    }
    private func coverage(_ rule: TripwireRule) -> String {
        if !rule.enabled { return "Disabled · retained alerts remain available" }
        if model.readError != nil { return "Coverage unknown · evidence store is unreadable" }
        if model.fileEventsReporting { return "Open-event feed reporting · rule scope and diagnostic source limits apply" }
        let ids = rule.kind == .application ? ["ai-open-files", "processes"] : ["ai-open-files"]
        let reporting = model.sensors.filter { ids.contains($0.id) && SensorPresentation($0).kind == .reporting }
        return reporting.isEmpty ? "Awaiting supported checks · start monitoring and inspect Sensor Status" : "SNAPSHOTS ONLY · brief file opens can be missed · enable event capture above"
    }
    private func choose() {
        let picker = NSOpenPanel(); picker.title = "Choose a tripwire boundary"
        picker.canChooseDirectories = draft.kind == .folder; picker.canChooseFiles = draft.kind != .folder
        picker.treatsFilePackagesAsDirectories = false; picker.allowsMultipleSelection = false
        picker.prompt = "Use this path"
        if draft.kind == .application { picker.directoryURL = URL(fileURLWithPath: "/Applications") }
        if picker.runModal() == .OK, let url = picker.url {
            draft.path = url.path
            if draft.name.isEmpty { draft.name = url.deletingPathExtension().lastPathComponent }
        }
    }
}
