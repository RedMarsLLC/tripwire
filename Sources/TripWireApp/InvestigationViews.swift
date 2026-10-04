import SwiftUI
import TripWireCore

struct FindingSummary: View {
    @EnvironmentObject var model: DashboardModel
    var finding: Finding
    var inspect: () -> Void
    var body: some View {
        Button(action: inspect) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    RiskBadge(assessment: model.view?.assessment(for: finding) ?? FindingAssessment(finding: finding))
                    Text(finding.title).font(.headline)
                    Spacer()
                    Label("Inspect finding", systemImage: "arrow.right").foregroundStyle(accent)
                }
                Text(finding.component).font(.callout.monospaced()).textSelection(.enabled)
                Text("Found: \(finding.whatHappened)")
                Text("Flagged because: \(finding.whyFlagged)").foregroundStyle(.secondary)
                Text("\(TimeText.iso(finding.timestamp)) · \(finding.confidence.rawValue) observation confidence · intent unknown")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).padding(18).cyberPanel()
                .clipShape(RoundedRectangle(cornerRadius: 10)).contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityLabel("Inspect finding: \(finding.title), \(finding.component)")
    }
}

struct FindingDetail: View {
    @EnvironmentObject var model: DashboardModel
    var finding: Finding
    var embedded = false
    @State private var evidence: FindingEvidence?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if !embedded { Button { model.route = .findings(nil) } label: { Label("All findings", systemImage: "arrow.left") }
                RiskBadge(assessment: model.view?.assessment(for: finding) ?? FindingAssessment(finding: finding)) }
            Text(finding.title).font(.title2.bold())
            Text(finding.component).font(.body.monospaced()).textSelection(.enabled)
            Text("Observed \(TimeText.iso(finding.timestamp)) · \(finding.severity.rawValue)").foregroundStyle(.secondary)
            FindingReviewEditor(finding: finding).id(finding.id)
            explanation("What was found", finding.whatHappened, icon: "eye")
            explanation("Why it was flagged", evidence?.explanation(for: finding) ?? finding.whyFlagged, icon: "flag")
            explanation("Which agent caused this?", associationExplanation, icon: "person.crop.circle.badge.questionmark")
            HStack(alignment: .top, spacing: 24) {
                explanation("Observation confidence", finding.confidence.rawValue, icon: "checkmark.magnifyingglass")
                explanation("Malicious intent", "Unknown — a finding establishes an observation, not intent.", icon: "questionmark.circle")
            }
            if let error {
                explanation("Evidence could not be read", error, icon: "exclamationmark.triangle")
            } else if let evidence {
                if !evidence.missingIDs.isEmpty {
                    explanation("Evidence is incomplete", "\(evidence.missingIDs.count) linked record(s) could not be found. The explanation cannot establish what those missing records contained.", icon: "exclamationmark.triangle")
                }
                Text("What changed").font(.title3.bold())
                Text("Before and after values from the linked observations. Detection time can be later than the actual change.").foregroundStyle(.secondary)
                ForEach(evidence.events) { event in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(event.observation.component).font(.headline)
                        Text("\(event.eventType) · \(TimeText.iso(event.timestamp)) · Source: \(event.sourceCollector)").font(.caption).foregroundStyle(.secondary)
                        ChangeTable(before: event.previousState, after: event.currentState)
                    }.padding(16).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
                }
                if evidence.events.isEmpty { Text("No supporting records are available. This is not evidence that no change occurred.").foregroundStyle(.orange) }
                explanation("Compared with the original baseline", finding.baselineDifference, icon: "square.stack.3d.up")
                Text("Evidence timeline").font(.title3.bold())
                ForEach(evidence.events) { event in
                    Button { model.route = .event(event.id) } label: {
                        HStack(alignment: .top) {
                            Image(systemName: "doc.text.magnifyingglass")
                            VStack(alignment: .leading, spacing: 5) {
                                Text("\(TimeText.iso(event.timestamp)) · \(event.eventType)").font(.caption.monospaced())
                                Text(event.observation.component)
                                Text("Source: \(event.sourceCollector) · Open evidence").font(.caption)
                            }
                            Spacer(); Image(systemName: "arrow.up.right")
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(12).cyberPanel()
                    }.buttonStyle(.plain).foregroundStyle(accent)
                }
            }
            explanation("What we cannot conclude", finding.limitations.joined(separator: "\n\n"), icon: "viewfinder")
            explanation("Suggested checks", finding.suggestedInvestigation.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "\n\n"), icon: "list.bullet.clipboard")
            DisclosureGroup("Technical references") {
                Text("Finding: \(finding.id)\nRule: \(finding.ruleID)\nRecorded explanation: \(finding.whyFlagged)\nEvidence: \(finding.eventIDs.joined(separator: ", "))").font(.caption.monospaced()).textSelection(.enabled)
            }
        }.task(id: finding.id) {
            evidence = nil; error = nil
            do { evidence = try model.evidence(for: finding) } catch { self.error = String(describing: error) }
        }
    }
    private var associationExplanation: String {
        let associations = (evidence?.events ?? []).compactMap { event -> String? in
            guard let app = event.observation.attributes["associatedApp"], let basis = event.observation.attributes["associationBasis"] else { return nil }
            return "\(app): \(basis)"
        }
        return associations.isEmpty ? "Not established in the available evidence. Nearby activity or a resource spike does not prove causation." : Array(Set(associations)).sorted().joined(separator: "\n") + "\nAssociation is not proof of an AI instruction, user authorization or malicious intent."
    }
    private func explanation(_ title: String, _ text: String, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon).font(.headline).foregroundStyle(accent)
            Text(text.isEmpty ? "Not recorded" : text).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(16).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct ChangeTable: View {
    var before: [String: String]?
    var after: [String: String]?
    private var keys: [String] { Set((before ?? [:]).keys).union((after ?? [:]).keys).filter { before?[$0] != after?[$0] }.sorted() }
    var body: some View {
        if keys.isEmpty {
            Text("No differing metadata fields in these linked values.").foregroundStyle(.secondary)
        } else {
            Grid(alignment: .topLeading, horizontalSpacing: 18, verticalSpacing: 10) {
                GridRow { Text("Field"); Text("Before"); Text("After") }.font(.caption.bold()).foregroundStyle(.secondary)
                ForEach(keys, id: \.self) { key in
                    GridRow {
                        Text(EvidenceValue.label(key)).fontWeight(.medium)
                        Text(EvidenceValue.display(before?[key], key: key)).foregroundStyle(.secondary).help(before?[key] ?? "Not recorded")
                        Text(EvidenceValue.display(after?[key], key: key)).foregroundStyle(accent).help(after?[key] ?? "Not recorded")
                    }
                }
            }.font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            if keys.contains("modifiedAt") { Text("File timestamps use your Mac's local time. Hover a value for its original recorded form.").font(.caption).foregroundStyle(.secondary) }
        }
    }
}

struct EventCard: View {
    @EnvironmentObject var model: DashboardModel
    var event: EvidenceEvent
    var expanded = false
    private var findings: [Finding] { Investigation.findings(for: event, in: model.view?.findings ?? []) }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(event.observation.component).font(.headline).textSelection(.enabled)
                    Text("\(TimeText.iso(event.timestamp)) · \(event.observation.eventClass.rawValue) · \(event.eventType)").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                Text(event.baselineStatus.rawValue).font(.caption.bold()).foregroundStyle(.orange)
            }
            if model.view == nil {
                Text("Related findings are unavailable while the store cannot be read.").font(.callout).foregroundStyle(.orange)
            } else if findings.isEmpty {
                Text("No finding is linked to this observation. Not every recorded change triggers a finding.").font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(findings) { finding in
                    Button { model.route = .findings(finding.id) } label: {
                        Label("Why flagged: \(finding.title)", systemImage: "arrow.up.right")
                    }.buttonStyle(.link)
                }
            }
            if expanded { details }
            else {
                Button { model.route = .event(event.id) } label: { Label("Inspect observation", systemImage: "doc.text.magnifyingglass") }.buttonStyle(.link)
            }
        }.frame(maxWidth: .infinity, alignment: .leading).padding(16).cyberPanel().clipShape(RoundedRectangle(cornerRadius: 10))
    }
    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            Divider()
            Text("Source: \(event.sourceCollector)").font(.headline)
            Text(event.evidence.joined(separator: "\n"))
            ChangeTable(before: event.previousState, after: event.currentState)
            if let process = event.observation.process {
                Text("Process: \(process.executablePath ?? "UNKNOWN")\nPID: \(process.pid.map(String.init) ?? "UNKNOWN") · Signing: \(process.signatureStatus ?? "UNKNOWN")")
            }
            Text("Source limitations").font(.headline)
            Text(Array(Set(event.limitations + event.observation.limitations)).sorted().joined(separator: "\n\n")).foregroundStyle(.secondary)
            DisclosureGroup("All recorded metadata") {
                ForEach(event.observation.attributes.keys.sorted(), id: \.self) { key in
                    Text("\(key): \(event.observation.attributes[key]!)")
                }
                Text("Evidence ID: \(event.id)")
            }
        }.font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
    }
}

struct EvidenceDetail: View {
    @EnvironmentObject var model: DashboardModel
    var id: String
    @State private var event: EvidenceEvent?
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Button { model.route = .events(.all) } label: { Label("All observations", systemImage: "arrow.left") }
            if let event { EventCard(event: event, expanded: true) }
            else { Text(error ?? "Loading evidence…").foregroundStyle(.secondary) }
        }.task(id: id) {
            event = nil; error = nil
            do {
                event = try model.event(id: id)
                if event == nil { error = "This evidence record is unavailable. Its absence here cannot establish that nothing happened." }
            } catch { self.error = "Evidence read failed: \(error)" }
        }
    }
}
