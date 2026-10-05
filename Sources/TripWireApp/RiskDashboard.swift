import SwiftUI
import TripWireCore

extension RiskLevel {
    var color: Color {
        switch self {
        case .critical: return Color(red: 1, green: 0.27, blue: 0.37)
        case .high: return Color(red: 1, green: 0.52, blue: 0.22)
        case .medium: return Color(red: 1, green: 0.79, blue: 0.25)
        case .low: return CyberTheme.cyan
        case .unassessed: return Color(red: 0.69, green: 0.63, blue: 0.82)
        }
    }
}

/// Seven-segment counters are drawn from the actual count. Text exposes the same
/// value to accessibility; blank/unavailable evidence is never rendered as zero.
struct SegmentCounter: View {
    var value: Int?
    var color: Color
    private static let digits = [[0,1,2,4,5,6], [2,5], [0,2,3,4,6], [0,2,3,5,6], [1,2,3,5], [0,1,3,5,6], [0,1,3,4,5,6], [0,2,5], [0,1,2,3,4,5,6], [0,1,2,3,5,6]]
    var body: some View {
        let text = value.map { String(format: "%02d", $0) } ?? "--"
        Canvas { context, size in
            let width = min(27, (size.width - CGFloat(text.count - 1) * 5) / CGFloat(text.count))
            let height = min(48, size.height), thick: CGFloat = 4
            for (index, character) in text.enumerated() {
                let x = CGFloat(index) * (width + 5)
                let active = character.wholeNumberValue.map { Self.digits[$0] } ?? [3]
                let segments = [CGRect(x: x + 4, y: 0, width: width - 8, height: thick),
                    CGRect(x: x, y: 4, width: thick, height: height/2 - 6), CGRect(x: x+width-thick, y: 4, width: thick, height: height/2-6),
                    CGRect(x: x+4, y: height/2-2, width: width-8, height: thick),
                    CGRect(x: x, y: height/2+2, width: thick, height: height/2-6), CGRect(x: x+width-thick, y: height/2+2, width: thick, height: height/2-6),
                    CGRect(x: x+4, y: height-thick, width: width-8, height: thick)]
                for (number, rect) in segments.enumerated() {
                    context.fill(CyberCut(cut: 2).path(in: rect), with: .color(color.opacity(active.contains(number) ? 1 : 0.09)))
                }
            }
        }.frame(height: 48).accessibilityLabel(value.map(String.init) ?? "Unavailable")
    }
}

struct RiskDashboard: View {
    @EnvironmentObject var model: DashboardModel
    @State private var selectedLevel: RiskLevel?
    @State private var reviewed = false
    @State private var selectedID: String?
    @State private var query = ""
    @State private var clearTargets: [FindingReviewTarget] = []
    @State private var confirmClear = false
    @State private var clearing = false
    @State private var queueMessage: String?
    @State private var queueError: String?
    private var queue: [Finding] {
        (model.view?.findings ?? []).filter { finding in
            let assessment = model.view!.assessment(for: finding)
            return (reviewed ? assessment.status != .open : assessment.status == .open)
                && (selectedLevel == nil || assessment.level == selectedLevel)
                && (query.isEmpty || [finding.title, finding.component, finding.whyFlagged].contains { $0.localizedCaseInsensitiveContains(query) })
        }.sorted {
            let a = model.view!.assessment(for: $0).level.order, b = model.view!.assessment(for: $1).level.order
            return a == b ? $0.timestamp > $1.timestamp : a < b
        }

    }
    private var selected: Finding? { queue.first { $0.id == selectedID } ?? queue.first }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            console
            HStack(alignment: .top, spacing: 16) {
                queueView.frame(minWidth: 190, idealWidth: 220, maxWidth: 240)
                VStack(alignment: .leading, spacing: 18) {
                    if let finding = selected {
                        HStack { Text("INSPECT / \(finding.id.prefix(8).uppercased())").tracking(2); Spacer(); RiskBadge(assessment: model.view!.assessment(for: finding)) }.font(.caption)
                        FindingDetail(finding: finding, embedded: true).id(finding.id)
                    } else {
                        Label(model.view == nil ? "Evidence unavailable" : "No findings in this queue", systemImage: "viewfinder").font(.title3.bold()).foregroundStyle(accent)
                        Text(model.view == nil ? "Retry reading the store. Risk counts are unknown." : "Choose another level or the Reviewed queue. An empty queue does not establish safety.").foregroundStyle(CyberTheme.muted)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(18).cyberPanel()
            }
            HStack {
                Button("Tripwire boundaries ↗") { model.route = .tripwires }
                Button("Security checks ↗") { model.route = .coverage(.all) }
                Button("Coverage gaps ↗") { model.route = .health }
                Spacer()
            }
        }
        .alert("Clear \(clearTargets.count) findings from this queue?", isPresented: $confirmClear) {
            Button("Cancel", role: .cancel) { clearTargets = [] }
            Button("Move to Reviewed") {
                let targets = clearTargets
                clearing = true; queueMessage = nil; queueError = nil
                Task {
                    do {
                        let count = try await model.clearQueue(targets)
                        selectedID = nil; queueMessage = "\(count) moved to Reviewed · Cleared."
                    } catch { queueError = String(describing: error) }
                    clearing = false; clearTargets = []
                }
            }
        } message: {
            Text("Only the open findings matching your current level and search when you clicked Clear queue will move to Reviewed with status Cleared. Evidence and risk levels stay intact. New findings remain open and future alerts stay enabled. You can reopen cleared findings from Reviewed.")
        }
    }
    private var console: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("RISK CONTROL").font(.system(size: 23, weight: .black, design: .monospaced)).tracking(3)
                    Text("PRIORITIZE · INSPECT · CORRECT").font(.system(size: 9, weight: .bold, design: .monospaced)).tracking(2).foregroundStyle(CyberTheme.muted)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 5) {
                    Text("\(model.view.map { _ in String(model.openFindings.count) } ?? "—") OPEN FINDINGS").font(.headline).foregroundStyle(accent)
                    Text("LOCAL EVIDENCE / USER REVIEW").font(.system(size: 9, design: .monospaced)).foregroundStyle(CyberTheme.muted)
                }
            }
            HStack(spacing: 9) {
                ForEach(RiskLevel.allCases) { level in
                    Button {
                        selectedLevel = selectedLevel == level && !reviewed ? nil : level
                        reviewed = false; selectedID = nil
                    } label: {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 5) {
                                Circle().fill(level.color).frame(width: 5, height: 5).shadow(color: level.color.opacity(0.8), radius: 4)
                                Text(level.label.uppercased()).font(.system(size: 10, weight: .bold, design: .monospaced)).lineLimit(1).minimumScaleFactor(0.8)
                                Spacer(minLength: 0)
                            }
                            SegmentCounter(value: model.view?.riskCounts[level], color: level.color)
                            HStack { Text("INSPECT"); Spacer(minLength: 0); Image(systemName: "arrow.up.right") }
                                .font(.system(size: 9, weight: .bold, design: .monospaced)).padding(.vertical, 6).padding(.horizontal, 7)
                                .background(level.color.opacity(0.12), in: CyberCut(cut: 4))
                                .overlay(CyberCut(cut: 4).stroke(level.color.opacity(0.4), lineWidth: 0.5))
                        }.foregroundStyle(level.color).padding(12).frame(maxWidth: .infinity)
                            .background(LinearGradient(colors: [level.color.opacity(selectedLevel == level ? 0.2 : 0.08), .black.opacity(0.7)], startPoint: .top, endPoint: .bottom), in: CyberCut(cut: 8))
                            .overlay(CyberCut(cut: 8).stroke(level.color.opacity(selectedLevel == level ? 1 : 0.4), lineWidth: selectedLevel == level ? 1.5 : 0.7))
                    }.buttonStyle(.plain).help(level.explanation).accessibilityLabel("\(level.label): \(model.view?.riskCounts[level].map(String.init) ?? "unavailable") open findings. Inspect")
                }
            }
            HStack(spacing: 8) {
                Text("▰ ▰ ▰").foregroundStyle(CyberTheme.pink)
                Text("Open findings by current classification. Risk is review priority; intent remains unknown.").font(.system(size: 10, design: .monospaced)).foregroundStyle(CyberTheme.muted)
                Spacer(minLength: 0)
            }
        }.padding(20).background(LinearGradient(colors: [Color(red: 0.05, green: 0.11, blue: 0.15), ink], startPoint: .top, endPoint: .bottom), in: CyberCut(cut: 18))
            .overlay(CyberCut(cut: 18).stroke(CyberTheme.line, lineWidth: 1.5))
            .overlay(alignment: .top) { HStack { Rectangle().fill(accent).frame(width: 85, height: 3); Spacer(); Rectangle().fill(CyberTheme.pink).frame(width: 85, height: 3) }.padding(.horizontal, 28).allowsHitTesting(false) }
    }
    private var queueView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text("REVIEW QUEUE").font(.headline).tracking(1); Spacer(); Text("\(queue.count)").foregroundStyle(accent) }
            Picker("Queue", selection: $reviewed) {
                Text("Open").tag(false); Text("Reviewed").tag(true)
            }.pickerStyle(.segmented).onChange(of: reviewed) { _, _ in selectedID = nil }
            HStack {
                Text(selectedLevel?.label.uppercased() ?? "ALL LEVELS").font(.caption).foregroundStyle(selectedLevel?.color ?? CyberTheme.muted)
                Spacer()
                if selectedLevel != nil {
                    Button("All levels") { selectedLevel = nil; selectedID = nil }
                        .help("Remove the risk-level filter. Findings are unchanged.")
                }
            }
            TextField("Search findings", text: $query).textFieldStyle(.roundedBorder)
            if !reviewed {
                Button(clearing ? "Clearing…" : "Clear queue (\(queue.count))…") {
                    guard let view = model.view else { return }
                    clearTargets = queue.map { FindingReviewTarget(findingID: $0.id, expectedReviewID: view.assessment(for: $0).latestReview?.id) }
                    confirmClear = true
                }.disabled(clearing || queue.isEmpty || model.view == nil)
                    .help("Move the displayed open findings to Reviewed. Keep evidence and future alerts.")
            }
            if let queueMessage { Text(queueMessage).font(.caption).foregroundStyle(accent) }
            if let queueError { Text(queueError).font(.caption).foregroundStyle(.orange) }
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(queue) { finding in
                        let assessment = model.view!.assessment(for: finding)
                        Button { selectedID = finding.id } label: {
                            VStack(alignment: .leading, spacing: 7) {
                                RiskBadge(assessment: assessment)
                                Text(finding.title).font(.system(size: 12, weight: .semibold)).lineLimit(3).foregroundStyle(.primary)
                                Text(finding.component).font(.system(size: 10, design: .monospaced)).lineLimit(2).truncationMode(.middle).foregroundStyle(CyberTheme.muted)
                                Text(TimeText.iso(finding.timestamp)).font(.system(size: 9, design: .monospaced)).foregroundStyle(CyberTheme.muted)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                                .background(assessment.level.color.opacity(selected?.id == finding.id ? 0.13 : 0.03), in: CyberCut(cut: 6))
                                .overlay(CyberCut(cut: 6).stroke(assessment.level.color.opacity(selected?.id == finding.id ? 0.8 : 0.18)))
                        }.buttonStyle(.plain).accessibilityLabel("Inspect \(finding.title), \(assessment.level.label), \(assessment.status.label)")
                    }
                }
            }.frame(height: 465)
            Text("Corrections preserve the original evidence and never suppress future alerts.").font(.caption).foregroundStyle(CyberTheme.muted)
        }.padding(16).cyberPanel()
    }
}

struct RiskBadge: View {
    var assessment: FindingAssessment
    var body: some View {
        Text("\(assessment.level.label.uppercased()) · \(assessment.status.label.uppercased())")
            .font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(assessment.level.color)
            .padding(.horizontal, 7).padding(.vertical, 4).background(assessment.level.color.opacity(0.09), in: CyberCut(cut: 3))
    }
}

struct FindingReviewEditor: View {
    @EnvironmentObject var model: DashboardModel
    var finding: Finding
    @State private var level = RiskLevel.unassessed
    @State private var status = FindingReviewStatus.open
    @State private var reason = ""
    @State private var revision: String?
    @State private var error: String?
    @State private var saved = false
    private var assessment: FindingAssessment { model.view?.assessment(for: finding) ?? FindingAssessment(finding: finding) }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text("CORRECT CLASSIFICATION").font(.system(size: 11, weight: .bold, design: .monospaced)).foregroundStyle(CyberTheme.pink); Spacer() }
            Text("Original suggestion: \(assessment.suggestedLevel.label). Confidence: \(finding.confidence.rawValue). These describe different things.").font(.caption).foregroundStyle(CyberTheme.muted).fixedSize(horizontal: false, vertical: true)
            HStack {
                Picker("Risk", selection: $level) { ForEach(RiskLevel.allCases) { Text($0.label).tag($0) } }
                Picker("Status", selection: $status) { ForEach(FindingReviewStatus.allCases) { Text($0.label).tag($0) } }
            }.font(.caption)
            TextField("Reason for correction (required, 500 characters max)", text: $reason, axis: .vertical).lineLimit(2...4).textFieldStyle(.roundedBorder)
            HStack {
                Button("Save correction") {
                    do { try model.review(finding, level: level, status: status, reason: reason, expectedReviewID: revision); load(); saved = true }
                    catch { self.error = String(describing: error); saved = false }
                }.disabled(reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || reason.count > 500 || (level == assessment.level && status == assessment.status))
                if saved { Text("Correction saved").font(.caption).foregroundStyle(accent) }
            }
            if let error { Text(error).font(.caption).foregroundStyle(.orange); Button("Reload current review") { model.refresh(); load() } }
            Text("This finding only. Original evidence stays intact. Future alerts remain enabled.").font(.caption).foregroundStyle(CyberTheme.muted)
            let reviews = (model.view?.findingReviews ?? []).filter { $0.findingID == finding.id }
            DisclosureGroup("Review history (\(reviews.count))") {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(reviews) { review in
                        Text("\(TimeText.iso(review.timestamp)) · \(review.previousLevel.label) → \(review.level.label) · \(review.previousStatus.label) → \(review.status.label)\n\(review.reason)").font(.caption).textSelection(.enabled).padding(.vertical, 4)
                    }
                    Text("Original: \(assessment.suggestedLevel.label) · Open · \(TimeText.iso(finding.timestamp))").font(.caption).foregroundStyle(CyberTheme.muted)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.font(.caption)
        }.padding(14).cyberPanel().onAppear { load() }
    }
    private func load() { level = assessment.level; status = assessment.status; revision = assessment.latestReview?.id; reason = ""; error = nil; saved = false }
}
