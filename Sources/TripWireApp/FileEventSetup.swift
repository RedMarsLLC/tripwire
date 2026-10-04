import SwiftUI
import AppKit
import TripWireCore

struct FileEventSetup: View {
    @EnvironmentObject var model: DashboardModel
    @State private var confirmAccess = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("FILE MONITORING · IN APP", systemImage: "shield.lefthalf.filled")
                .font(.headline).foregroundStyle(accent)
            Text(model.fileMonitor.phase == .reporting ? "REPORTING · LIMITED COVERAGE" : model.fileMonitor.phase == .authorizing ? "WAITING FOR ADMINISTRATOR APPROVAL" : model.fileMonitor.phase == .stopping ? "STOPPING…" : model.fileMonitor.phase.active ? "WAITING FOR VALID FILE EVENTS" : "FILE EVENT MONITOR IS OFF")
                .font(.headline).foregroundStyle(model.fileMonitor.phase == .reporting ? accent : .orange)
            Text(model.fileMonitor.detail).font(.callout).fixedSize(horizontal: false, vertical: true)
            HStack {
                if model.fileMonitor.phase.active {
                    Button("Stop file monitoring") { model.fileMonitor.stop() }.disabled(model.fileMonitor.phase == .stopping)
                } else {
                    Button("Enable file monitoring…") { confirmAccess = true }
                }
                Button("Full Disk Access settings ↗") { model.fileMonitor.openPrivacySettings() }
                Button("Inspect feed status ↗") { model.route = .coverage(.all) }
            }
            Text("No terminal or developer account needed. Approve the administrator prompt, grant TripWire Full Disk Access in macOS Settings, then quit and reopen TripWire if macOS requests it. Start file monitoring again after reopening. The helper runs only for this app session; Stop monitoring or quitting the app stops it.")
                .font(.caption).foregroundStyle(CyberTheme.muted)
            if model.fileEventsReporting && !model.fileMonitor.phase.active {
                Text("A separate diagnostic receiver is reporting to this store. Stop that receiver before enabling the in-app monitor; TripWire will not start two feeds.").font(.caption).foregroundStyle(.orange)
            }
            DisclosureGroup("What this monitors and what access you are granting") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("The bundled session helper runs Apple's /usr/bin/eslogger with five fixed notification types: open, write, close, rename and unlink. Only configured paths are retained, using each rule's account or AI-associated scope. TripWire and its evidence store stay under your normal account.")
                    Text("Full Disk Access is a broad macOS permission. TripWire retains path/process/operation metadata, not document contents, process arguments, environment values or mouse/keyboard input. Permissions are approved by you in System Settings and can be revoked there.")
                    Text("This local compatibility source uses Apple's diagnostic tool and a deprecated administrator-launch API. It is not a native Endpoint Security deployment. macOS updates may make it unavailable; format errors, stale input and interruptions remain visible. No service, login item or permission is installed automatically. A production native provider still needs developer signing and Apple's entitlement; people using that release would not need developer accounts.")
                    Text("A reported open does not prove bytes were read. Aliases, other accounts, unrecognized AI identities and event loss can leave gaps. File-handle snapshots continue independently and can miss brief activity.")
                }.font(.caption).foregroundStyle(CyberTheme.muted).padding(.top, 8)
            }
        }.padding(18).cyberPanel()
        .alert("Enable file monitoring?", isPresented: $confirmAccess) {
            Button("Enable") { model.fileMonitor.start(storeURL: model.storeURL) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("macOS will ask to run TripWire's bundled session helper as administrator. It starts only the fixed Apple event tool; it installs no service. Full Disk Access must also be approved in Settings. Only matching metadata is retained locally. Stopping monitoring or quitting TripWire ends the helper.")
        }
    }
}
