import Foundation
import TripWireCore
import TripWireCollectors

enum Screen: String, CaseIterable, Identifiable {
    case tripwires = "TRIPWIRES"
    case files = "FILE ACTIVITY", security = "SECURITY WATCH", agents = "AGENT ACTIVITY", overview = "OVERVIEW", events = "OBSERVATIONS", findings = "FINDINGS", applications = "APPLICATIONS", network = "NETWORK", processes = "PROCESSES", persistence = "PERSISTENCE", hardware = "HARDWARE", system = "SYSTEM CHANGES", baseline = "BASELINE", coverage = "SENSOR STATUS", health = "WATCHDOG HEALTH"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .tripwires: return "slider.horizontal.3"
        case .files: return "doc.text.magnifyingglass"
        case .security: return "shield.lefthalf.filled"
        case .applications: return "app.badge"
        case .agents: return "terminal"
        case .overview: return "waveform.path.ecg"
        case .events: return "list.bullet.rectangle"
        case .findings: return "exclamationmark.triangle"
        case .network: return "network"
        case .processes: return "cpu"
        case .persistence: return "clock.arrow.circlepath"
        case .hardware: return "externaldrive"
        case .system: return "gearshape.2"
        case .baseline: return "square.stack.3d.up"
        case .coverage: return "viewfinder"
        case .health: return "heart.text.square"
        }
    }
}

enum EventScope: String { case all = "All observations", changes = "Observed changes" }
enum InventoryScope { case all, unknown }
enum SensorScope: Equatable { case all, reporting, attention, unavailable, sensor(String) }

enum DashboardRoute: Equatable {
    case tripwires, tripwireAlerts
    case files, security, agents(String?), appResources, spike, overview, findings(String?), events(EventScope), event(String)
    case inventory(Screen, InventoryScope), coverage(SensorScope), health

    var screen: Screen {
        switch self {
        case .tripwires: return .tripwires
        case .files: return .files
        case .security: return .security
        case .agents, .appResources: return .agents
        case .overview, .spike: return .overview
        case .findings, .tripwireAlerts: return .findings
        case .events, .event: return .events
        case .inventory(let screen, _): return screen
        case .coverage: return .coverage
        case .health: return .health
        }
    }
    static func page(_ screen: Screen) -> Self {
        switch screen {
        case .tripwires: return .tripwires
        case .files: return .files
        case .security: return .security
        case .agents: return .agents(nil)
        case .overview: return .overview
        case .events: return .events(.all)
        case .findings: return .findings(nil)
        case .coverage: return .coverage(.all)
        case .health: return .health
        default: return .inventory(screen, .all)
        }
    }
}

enum DashboardMetric: CaseIterable, Equatable {
    case findings, tripwireAlerts, changes, unknowns, gaps, sockets, reporting
    var destination: DashboardRoute {
        switch self {
        case .findings: return .findings(nil)
        case .tripwireAlerts: return .tripwireAlerts
        case .changes: return .events(.changes)
        case .unknowns: return .inventory(.baseline, .unknown)
        case .gaps: return .health
        case .sockets: return .inventory(.network, .all)
        case .reporting: return .coverage(.reporting)
        }
    }
}

enum Investigation {
    static func isChange(_ event: EvidenceEvent) -> Bool { ["NEW", "CHANGED", "REMOVED"].contains(event.eventType) }
    static func isUnknown(_ record: InventoryRecord) -> Bool {
        record.baselineStatus == .unknown || record.observation.attributes.values.contains {
            $0.hasPrefix("UNKNOWN") || $0.hasPrefix("NOT OBSERVABLE") || $0.hasPrefix("UNAVAILABLE")
        }
    }
    static func findings(for event: EvidenceEvent, in findings: [Finding]) -> [Finding] {
        findings.filter { $0.eventIDs.contains(event.id) }
    }
}

struct SensorPresentation {
    enum Kind { case reporting, attention, unavailable, optional, stopped, unknown }
    var kind: Kind
    var title: String
    var explanation: String
    var nextStep: String

    init(_ sensor: SensorHealth) {
        let sensor = sensor.effective()
        if sensor.id == OpenEventBridge.id {
            let current = sensor.effective(staleAfter: 10)
            kind = [.active, .degraded].contains(current.state) && current.visibility == .limited ? .reporting : current.state == .stopped ? .stopped : .attention
            title = kind == .reporting ? "Open-event feed reporting · limited" : "Open-event feed is not reporting"
            explanation = current.detail
            nextStep = "Open Tripwires → Set up foreground event capture. Keep the explicitly authorized eslogger pipe running in its terminal. Start monitoring controls snapshots and cannot start this separate feed. Check format, permission and sequence-gap reports; missing input never establishes coverage."
        } else if CollectorRegistry.unavailable.contains(where: { $0.descriptor.id == sensor.id }) {
            kind = .unavailable; title = "Not available in this build"
            explanation = sensor.detail
            switch sensor.id {
            case "endpoint-security": nextStep = "Development needed: implement the OS event collector, obtain Apple’s Endpoint Security entitlement, then deploy a signed collector with explicit user approval. Open-file snapshots are available in File Activity, but no setting enables a complete file event audit or reliable AI-action attribution."
            case "network-extension": nextStep = "Development needed: implement a signed network-flow provider and an explicit deployment/approval flow. Existing socket checks remain available; no filter is installed by Start monitoring."
            default: nextStep = "Development needed: implement a supported metadata collector for this feature. This is not a broken setting or a permission you can fix in this build."
            }
        } else if sensor.id == "canaries" && sensor.state == .stopped && (sensor.visibility == .unavailable || !sensor.initialized) {
            kind = .optional; title = "Optional canary not configured"
            explanation = sensor.detail
            nextStep = "This sensor checks only markers you explicitly create with tripwire canary create NAME. It does not watch arbitrary documents or attribute reads."
        } else if sensor.state == .unsupported {
            kind = .attention; title = "Unsupported source"
            explanation = sensor.detail
            nextStep = "This source cannot report in the current environment. Review its scope and limitations."
        } else if sensor.state == .error || sensor.state == .permissionMissing || sensor.state == .dataLossDetected || sensor.visibility == .unavailable {
            kind = .attention; title = sensor.state == .permissionMissing ? "Access needed" : "Needs attention"
            explanation = sensor.detail
            nextStep = "Retry with Take snapshot (or keep monitoring on), then inspect this source’s reported error below. If it continues, the collector or source access needs repair. A read failure alone does not tell us which permission is missing."
        } else if sensor.state == .active || sensor.state == .degraded {
            kind = .reporting
            title = sensor.visibility == .unknown || sensor.visibility == .notObservable ? "Reporting · visibility unknown" : sensor.visibility == .available && sensor.state == .active ? "Reporting" : "Reporting · limited visibility"
            explanation = sensor.detail
            nextStep = sensor.detail.localizedCaseInsensitiveContains("partial inventory") ? "Some entries could not be checked. Review the paths/reasons above, confirm that the source is readable, and retry a snapshot. Missing entries cannot be treated as absent." : "This check is running within the scope shown below. Limits such as polling gaps, unobserved file accesses or unknown attribution need additional collectors; restarting does not remove them."
        } else if sensor.initialized || sensor.lastSuccess != nil {
            kind = .stopped; title = "Not running / reports may be stale"
            explanation = sensor.detail
            nextStep = "Start monitoring for repeated snapshots, or take a snapshot for one check. Historical evidence is retained."
        } else {
            kind = .unknown; title = "Not checked yet"
            explanation = "No successful report is available for this sensor."
            nextStep = "Take a snapshot or start monitoring. Its visibility remains unknown until a check succeeds."
        }
    }
    func matches(_ scope: SensorScope, id: String) -> Bool {
        switch scope {
        case .all: return true
        case .reporting: return kind == .reporting
        case .attention: return kind == .attention || kind == .stopped || kind == .unknown
        case .unavailable: return kind == .unavailable
        case .sensor(let requested): return id == requested
        }
    }
}

struct FindingEvidence {
    var events: [EvidenceEvent]
    var missingIDs: [String]
    init(finding: Finding, read: (String) throws -> EvidenceEvent?) throws {
        var events: [EvidenceEvent] = [], missing: [String] = []
        for id in finding.eventIDs {
            if let event = try read(id) { events.append(event) } else { missing.append(id) }
        }
        self.events = events.sorted { $0.timestamp < $1.timestamp }
        self.missingIDs = missing
    }
    func explanation(for finding: Finding) -> String {
        guard finding.ruleID == "inventory-change-v1", missingIDs.isEmpty, events.count == 1, let event = events.first else { return finding.whyFlagged }
        let purpose: String
        switch event.observation.eventClass {
        case .application: purpose = FindingEngine.reason(for: event)
        case .health: purpose = "TripWire monitors its own executable and evidence-store metadata. Changes are flagged so you can check whether an expected update or another change explains them."
        case .persistence: purpose = "Startup and persistence changes are flagged because they can affect what runs automatically."
        case .listener: purpose = "Listening-service changes are flagged so you can review services accepting connections. A listening socket does not establish external reachability."
        case .configuration: purpose = "Changes to monitored security or network settings are flagged for review."
        case .extensions: purpose = FindingEngine.reason(for: event)
        case .hardware: purpose = "Device inventory changes are flagged so you can review newly observed, changed or missing hardware."
        case .canary: purpose = "This explicitly created marker is monitored for content or metadata changes. Reads and the responsible process are not observable."
        default: return finding.whyFlagged
        }
        let trigger: String
        switch event.eventType {
        case "NEW": trigger = "This entry was first observed after the initial baseline."
        case "REMOVED": trigger = "This entry was no longer observed in a successful check of the source's declared scope."
        default: trigger = "This record differed from the previous check."
        }
        return "\(purpose)\n\n\(trigger)\(event.baselineStatus == .known ? " It now matches the original observed baseline." : "") Malicious intent remains unknown."
    }
}

enum EvidenceValue {
    static func label(_ key: String) -> String {
        ["modifiedAt": "Modified time", "sizeBytes": "File size", "sha256": "File fingerprint (SHA-256)",
         "ownerUID": "Owner user ID", "groupGID": "Owner group ID", "mode": "File permissions",
         "executable": "Executable", "path": "Path", "signatureStatus": "Signature status",
         "teamID": "Signing team ID", "pid": "Process ID", "parentPID": "Parent process ID"][key] ?? key
    }
    static func display(_ value: String?, key: String) -> String {
        guard let value else { return "Not recorded" }
        if key == "modifiedAt", let seconds = Double(value), seconds.isFinite, (0...253402300799).contains(seconds) {
            return Date(timeIntervalSince1970: seconds).formatted(date: .abbreviated, time: .standard)
        }
        if key == "sizeBytes", let bytes = Int64(value), bytes >= 0 { return "\(bytes.formatted()) bytes" }
        return value
    }
}
