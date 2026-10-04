import SwiftUI
import AppKit
import TripWireCore
import TripWireCollectors

struct FileEventSetup: View {
    @EnvironmentObject var model: DashboardModel
    @State private var expanded = false
    private func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private var command: String {
        "/usr/bin/sudo /usr/bin/eslogger open | " + quote(AgentIntegrationProbe.defaultExecutable.path) + " file-events --db " + quote(model.storeURL.path)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(model.fileEventsReporting ? "BRIEF-OPEN FEED REPORTING · LIMITED SCOPE" : "BRIEF FILE OPENS CAN BE MISSED · SETUP REQUIRED", systemImage: "exclamationmark.shield")
                .font(.headline).foregroundStyle(model.fileEventsReporting ? accent : .orange)
            Text(model.fileEventsReporting ? "The foreground open-event feed is reporting. Only configured paths associated with recognized AI apps are retained. Inspect Sensor Status for source limits and interruptions." : "Your rule is saved, but open-file snapshots only see handles still open at check time. A file opened and closed between checks can produce no alert. Faster polling cannot guarantee catching it.")
                .font(.callout).fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("Set up foreground event capture on macOS", isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("This optional diagnostic bridge uses Apple's eslogger open notifications. It needs your explicit administrator authorization and Full Disk Access for the terminal running it. TripWire does not grant permissions or install a background service.")
                    Text("1. In a terminal you authorize, enable Full Disk Access if required by macOS.\n2. Run the command below. Only eslogger runs as administrator; TripWire stays your normal user.\n3. Keep the terminal open. Verify a recent File-open event bridge report in Sensor Status before testing the boundary.\n4. Press Control-C to stop. The page will show when the feed stops reporting.")
                    Text(command).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).padding(12).background(.black.opacity(0.3))
                    HStack {
                        Button("Copy setup command") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(command, forType: .string) }
                        Button("Inspect event-feed status ↗") { model.route = .coverage(.all) }
                    }
                    Text("Diagnostic format only, not a production Endpoint Security deployment. Unknown formats, stale reports, unavailable audit identities and unrecognized agents are not treated as coverage. A reported open is not proof of bytes read/written. No documents or tool arguments are retained. Standard input is unauthenticated and can be forged by the same user.").foregroundStyle(CyberTheme.muted)
                }.font(.caption).padding(.top, 12)
            }.foregroundStyle(accent)
        }.padding(18).cyberPanel()
    }
}
