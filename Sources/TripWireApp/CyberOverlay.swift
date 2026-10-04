import SwiftUI
import AppKit
import TripWireCore

/// The supplied artwork is the entire visible frame; the native window is clear.
struct CyberOverlayPanel: View {
    static let aspect = OverlayLayout.aspect
    private static let cyan = Color(red: 0.05, green: 0.91, blue: 1)
    private static let pink = Color(red: 1, green: 0.14, blue: 0.69)
    private static let muted = Color(red: 0.52, green: 0.69, blue: 0.75)
    private static let artworkBundle: Bundle = {
        // SwiftPM's generated accessor checks beside the executable/build tree.
        // A distributable .app keeps this bundle inside Contents/Resources.
        if let resources = Bundle.main.resourceURL,
           let packaged = Bundle(url: resources.appendingPathComponent("TripWire_TripWireApp.bundle")) {
            return packaged
        }
        return .module
    }()
    private static let artwork = artworkBundle.url(forResource: "OverlayFrame", withExtension: "png").flatMap(NSImage.init(contentsOf:))
    private static let verticalArtwork = artworkBundle.url(forResource: "OverlayFrameVertical", withExtension: "png").flatMap(NSImage.init(contentsOf:))
    private static let miniArtwork = artworkBundle.url(forResource: "OverlayFrameMini", withExtension: "png").flatMap(NSImage.init(contentsOf:))

    var view: StoreView?
    var sensors: [SensorHealth]
    var error: String?
    var sampling: Bool
    var running: Bool
    var checkSummary: CheckSummary
    var compact: Bool
    var size: OverlaySize
    var orientation: OverlayOrientation
    var resources: ResourceMetrics
    var appResources: AppResourceMetrics
    var hooks: AgentActivityView
    var hookHistory: AgentActivityHistory
    var metricsLive: Bool
    var snapshot: () -> Void
    var startMonitoring: () -> Void
    var dashboard: () -> Void
    var inspect: (DashboardRoute) -> Void
    var inspectRange: (MetricInspection) -> Void
    var minimize: () -> Void
    var expand: () -> Void
    var resize: () -> Void
    var changeOrientation: (OverlayOrientation) -> Void
    var moveToEdge: (OverlayEdge) -> Void
    var close: () -> Void

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var hasSample: Bool { view.map { $0.sampledAt != "NEVER" } ?? false }
    private var openFindings: [Finding] { (view?.findings ?? []).filter { view?.assessment(for: $0).status == .open } }
    private var boundaryAlerts: [Finding] { openFindings.filter { $0.ruleID.hasPrefix("user-tripwire:") } }
    private var findingsTitle: String { boundaryAlerts.isEmpty ? "FINDINGS" : "ALERTS" }
    private var findingsValue: String { view == nil ? "—" : String(boundaryAlerts.isEmpty ? openFindings.count : boundaryAlerts.count) }
    private var findingsDestination: DashboardMetric { boundaryAlerts.isEmpty ? .findings : .tripwireAlerts }
    private var sockets: Int? {
        view?.inventory.filter { [.network, .listener].contains($0.observation.eventClass) }.count
    }
    private func count(_ value: Int?) -> String {
        guard hasSample, let value else { return "—" }
        return String(value)
    }

    var body: some View {
        Group {
            switch orientation {
            case .horizontal: horizontalPanel
            case .vertical: verticalPanel
            case .mini: miniPanel
            }
        }
    }

    private var horizontalPanel: some View {
        ZStack(alignment: .topLeading) {
            // This well extends beneath the artwork's inner edge, never outside
            // its silhouette. It is not a second window/card around the frame.
            CutCornerWell()
                .fill(LinearGradient(
                    colors: [Color(red: 0.015, green: 0.06, blue: 0.095), .black],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                ))
                .opacity(reduceTransparency ? 1 : 0.86)
                .frame(width: 833, height: 259)
                .offset(x: 83, y: 222)

            Canvas { context, size in
                var grid = Path()
                for x in stride(from: CGFloat(0), through: size.width, by: 24) {
                    grid.move(to: CGPoint(x: x, y: 0)); grid.addLine(to: CGPoint(x: x, y: size.height))
                }
                for y in stride(from: CGFloat(0), through: size.height, by: 24) {
                    grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: size.width, y: y))
                }
                context.stroke(grid, with: .color(Self.cyan.opacity(0.045)), lineWidth: 0.5)
            }
            .frame(width: 790, height: 219)
            .offset(x: 106, y: 244)
            .allowsHitTesting(false)
            .accessibilityHidden(true)

            if let artwork = Self.artwork {
                Image(nsImage: artwork)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 1000, height: 1000 * Self.aspect)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            } else {
                Text("Overlay artwork unavailable — reopen the packaged app.")
                    .foregroundStyle(.red).offset(x: 118, y: 200)
            }

            // Keep the actual data wholly inside the transparent center opening.
            Group {
                if compact { compactDataPanel }
                else { dataPanel }
            }
                .frame(width: 768, height: 217, alignment: .topLeading)
                .offset(x: 118, y: 247)

            // Match the controls already painted in the supplied PNG. These are
            // accessible hit targets, not another set of system titlebar buttons.
            artworkButton("Minimize overlay", action: minimize).offset(x: 840, y: 68)
            artworkButton("Expand overlay", action: expand).offset(x: 881, y: 68)
            artworkButton("Close overlay", action: close).offset(x: 921, y: 68)
        }
        .frame(width: 1000, height: 1000 * Self.aspect)
        .font(.system(size: 11, design: .monospaced))
        .foregroundStyle(Color.white.opacity(0.94))
    }

    // Larger canvas type stays readable after the artwork scales to 480 points.
    // Detailed sensor/event tables remain one click away in the dashboard.
    private var compactDataPanel: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 24) {
                compactMetric(findingsTitle, value: findingsValue, destination: findingsDestination, color: Self.pink)
                compactMetric("CHECKS ↗", value: checkSummary.value, destination: .reporting, color: Self.cyan)
                Spacer(minLength: 0)
                layoutMenu
                shrinkButton
            }
            RetroMetricsStrip(resources: resources, appResources: appResources, hooks: hooks, hookHistory: hookHistory, live: metricsLive, compact: true,
                              inspect: { inspect(.agents($0)) }, inspectResources: { inspect(.appResources) }, inspectRange: inspectRange)
            HStack {
                Button(action: showCheckStatus) {
                    Text(checkSummary.headline)
                        .font(.system(size: 18, weight: .medium, design: .monospaced)).foregroundStyle(.yellow).lineLimit(1)
                }.buttonStyle(.plain).help(checkSummary.explanation)
                Spacer(minLength: 10)
                fileActivityButton(fontSize: 18)
                Button(action: dashboard) {
                    Label("Dashboard", systemImage: "arrow.up.right")
                        .font(.system(size: 20, weight: .semibold, design: .monospaced)).foregroundStyle(Self.cyan)
                }.buttonStyle(.plain)
            }
            if let finding = openFindings.first {
                Button { inspect(.findings(finding.id)) } label: {
                    Text("LATEST ↗ \(finding.title)").font(.system(size: 17, design: .monospaced))
                        .foregroundStyle(Self.pink).lineLimit(1)
                }.buttonStyle(.plain).help("\(finding.whatHappened)\n\(finding.whyFlagged)")
                    .accessibilityLabel("Inspect latest finding: \(finding.title)")
            } else {
                Text("\(running ? "MONITORING" : sampling ? "CHECKING…" : "STORE VIEW") · No findings does not establish safety.")
                    .font(.system(size: 16, design: .monospaced)).foregroundStyle(Self.muted).lineLimit(1)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func compactMetric(_ title: String, value: String, destination: DashboardMetric, color: Color) -> some View {
        Button { inspect(destination == .reporting ? .coverage(.all) : destination.destination) } label: {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(value).font(.system(size: 26, weight: .semibold, design: .monospaced)).foregroundStyle(color)
                Text(title).font(.system(size: 17, weight: .semibold, design: .monospaced)).foregroundStyle(Self.muted)
            }.contentShape(Rectangle())
        }.buttonStyle(.plain).help(destination == .reporting ? checkSummary.catalogExplanation : "Inspect findings")
            .accessibilityLabel("\(title): \(value). Inspect details")
    }

    private var dataPanel: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                HStack(spacing: 7) {
                    Rectangle().fill(Self.cyan).frame(width: 3, height: 10)
                    Text("OBSERVATION CONSOLE").tracking(2).foregroundStyle(Self.cyan)
                }
                Spacer()
                Text("LAST SNAPSHOT  \(view?.sampledAt ?? "UNKNOWN")")
                    .foregroundStyle(Self.muted)
                layoutMenu
                shrinkButton
            }.font(.system(size: 8, weight: .semibold, design: .monospaced))

            HStack(spacing: 12) {
                metric(findingsTitle + " ↗", value: findingsValue, note: "recorded · what and why", color: Self.pink, destination: findingsDestination)
                metric("OBSERVED CHANGES ↗", value: count(view?.changes), note: "inspect last 200 events", color: Self.cyan, destination: .changes)
                metric("SOCKET RECORDS ↗", value: count(sockets), note: "stored · inspect details", color: Self.cyan, destination: .sockets)
                metric("SECURITY CHECKS ↗", value: checkSummary.value, note: checkSummary.countNote, color: Self.cyan, destination: .reporting)
            }

            Rectangle().fill(LinearGradient(colors: [Self.cyan.opacity(0.6), Self.pink.opacity(0.3)], startPoint: .leading, endPoint: .trailing)).frame(height: 1)

            RetroMetricsStrip(resources: resources, appResources: appResources, hooks: hooks, hookHistory: hookHistory, live: metricsLive, compact: false,
                              inspect: { inspect(.agents($0)) }, inspectResources: { inspect(.appResources) }, inspectRange: inspectRange)

            HStack(spacing: 10) {
                Button(action: showCheckStatus) {
                  VStack(alignment: .leading, spacing: 3) {
                    Text(checkSummary.headline)
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.yellow)
                    Text("Click for the reason and next step. Checks have limited scope.")
                        .font(.system(size: 8, design: .monospaced)).foregroundStyle(Self.muted)
                }
                  .lineLimit(1)
                }.buttonStyle(.plain)
                .help(checkSummary.explanation)
                Spacer(minLength: 4)
                fileActivityButton(fontSize: 10)
                investigationMenu
                actionButton(running ? "MONITORING" : sampling ? "CHECKING…" : "START CHECKS", color: Self.cyan, action: startMonitoring)
                    .disabled(sampling)
                actionButton("DASHBOARD", color: Self.pink, action: dashboard)
            }
        }
    }

    private func fileActivityButton(fontSize: CGFloat) -> some View {
        Button { inspect(.files) } label: {
            Label("Files", systemImage: "doc.text.magnifyingglass")
                .font(.system(size: fontSize, weight: .semibold, design: .monospaced)).foregroundStyle(Self.cyan)
        }.buttonStyle(.plain).accessibilityLabel("Inspect AI file activity")
            .help("Inspect observed open files, holding processes, associated AI apps and sensitive-location findings. Snapshot coverage; actual reads/writes are not audited.")
    }

    private func showCheckStatus() {
        if checkSummary.paused { startMonitoring() }
        else { inspect(checkSummary.destination) }
    }

    private var layoutMenu: some View {
        Menu {
            Button { changeOrientation(.horizontal) } label: {
                Label("Horizontal", systemImage: orientation == .horizontal ? "checkmark" : "rectangle")
            }
            Button { changeOrientation(.vertical) } label: {
                Label("Vertical", systemImage: orientation == .vertical ? "checkmark" : "rectangle.portrait")
            }
            Button { changeOrientation(.mini) } label: {
                Label("Super compact", systemImage: orientation == .mini ? "checkmark" : "square")
            }
            Divider()
            Button("Move to left edge") { moveToEdge(.left) }
            Button("Move to right edge") { moveToEdge(.right) }
            Button("Move to top edge") { moveToEdge(.top) }
            Divider()
            Button("Configure tripwires…") { inspect(.tripwires) }
            Button("Recorded tripwire alerts") { inspect(.tripwireAlerts) }
        } label: {
            Text("Layout").font(.system(size: orientation == .mini ? 13 : orientation == .vertical ? 15 : compact ? 19 : 11, weight: .semibold, design: .monospaced))
        }.menuStyle(.borderlessButton).fixedSize()
            .foregroundStyle(Self.cyan)
            .accessibilityLabel("Overlay layout")
            .help("Choose horizontal, vertical or super compact; place the visible frame against a screen edge")
    }

    private var miniPanel: some View {
        ZStack(alignment: .topLeading) {
            MiniOverlayWell()
                .fill(LinearGradient(colors: [Color(red: 0.015, green: 0.06, blue: 0.095), .black], startPoint: .topLeading, endPoint: .bottomTrailing))
                .opacity(reduceTransparency ? 1 : 0.86)
                .frame(width: 360, height: 360 * OverlayOrientation.mini.aspect)
            if let artwork = Self.miniArtwork {
                Image(nsImage: artwork).resizable().interpolation(.high)
                    .frame(width: 360, height: 360 * OverlayOrientation.mini.aspect)
                    .allowsHitTesting(false).accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    layoutMenu
                    Spacer(minLength: 0)
                    if size == .expanded {
                        Button(action: resize) { Label("Shrink", systemImage: "arrow.down.right.and.arrow.up.left") }
                            .buttonStyle(.plain).foregroundStyle(Self.cyan).accessibilityLabel("Shrink overlay")
                    }
                }.frame(height: 17)
                HStack(spacing: 10) {
                    Button { inspect(findingsDestination.destination) } label: { Text("\(findingsValue) \(findingsTitle.lowercased()) ↗").foregroundStyle(Self.pink) }
                        .help("Recorded findings or tripwire alerts. Open what was observed and why it was flagged; these are not confirmed incidents.")
                    Spacer(minLength: 0)
                    Button { inspect(.coverage(.all)) } label: { Text(checkSummary.value + " ↗").foregroundStyle(Self.cyan) }
                        .help(checkSummary.catalogExplanation).accessibilityLabel("Security checks: \(checkSummary.value). Inspect details")
                }.buttonStyle(.plain).lineLimit(1).frame(height: 17)
                MiniMetricsStrip(resources: resources, apps: appResources, hooks: hooks, hookHistory: hookHistory,
                                 live: metricsLive, inspectApps: { inspect(.appResources) }, inspectRange: inspectRange)
                Button(action: showCheckStatus) {
                    Text(checkSummary.headline).foregroundStyle(.yellow).lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }.buttonStyle(.plain).help(checkSummary.explanation)
                    .frame(height: 30, alignment: .topLeading)
                HStack {
                    fileActivityButton(fontSize: 13)
                    Spacer(minLength: 0)
                    Button(action: dashboard) { Label("Dashboard", systemImage: "arrow.up.right").foregroundStyle(Self.cyan) }
                        .buttonStyle(.plain)
                }.frame(height: 17)
            }
            .font(.system(size: 13, weight: .semibold, design: .monospaced))
            .frame(width: 214, height: 153, alignment: .topLeading).offset(x: 62, y: 136)

            miniArtworkButton("Minimize overlay", action: minimize).offset(x: 227, y: 54)
            miniArtworkButton("Expand overlay", action: expand).offset(x: 248, y: 54)
            miniArtworkButton("Close overlay", action: close).offset(x: 268, y: 54)
        }.frame(width: 360, height: 360 * OverlayOrientation.mini.aspect)
            .foregroundStyle(Color.white.opacity(0.94))
    }

    private func miniArtworkButton(_ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Color.white.opacity(0.001).frame(width: 21, height: 26).contentShape(Rectangle()) }
            .buttonStyle(.plain).help(label).accessibilityLabel(label)
    }

    private var verticalPanel: some View {
        ZStack(alignment: .topLeading) {
            // Keep the data well inside the supplied frame's transparent opening.
            VerticalOverlayWell()
                .fill(LinearGradient(colors: [Color(red: 0.015, green: 0.06, blue: 0.095), .black], startPoint: .topLeading, endPoint: .bottomTrailing))
                .opacity(reduceTransparency ? 1 : 0.86)
                .frame(width: 360, height: 1080)
            if let artwork = Self.verticalArtwork {
                Image(nsImage: artwork).resizable().interpolation(.high)
                    .frame(width: 360, height: 1080)
                    .allowsHitTesting(false).accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    layoutMenu
                    Spacer(minLength: 0)
                    verticalControl("Minimize overlay", symbol: "minus", action: minimize)
                    verticalControl("Expand overlay", symbol: "square", action: expand)
                    verticalControl("Close overlay", symbol: "xmark", action: close)
                }.frame(height: 26)
                ScrollView(.vertical) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(alignment: .top, spacing: 10) {
                            verticalMetric(findingsTitle + " ↗", value: findingsValue, color: Self.pink) { inspect(findingsDestination.destination) }
                            verticalMetric("CHECKS ↗", value: checkSummary.value, color: Self.cyan) { inspect(.coverage(.all)) }
                                .help(checkSummary.catalogExplanation)
                        }
                        Rectangle().fill(Self.cyan.opacity(0.35)).frame(height: 1)
                        RetroMetricsStrip(resources: resources, appResources: appResources, hooks: hooks, hookHistory: hookHistory,
                                          live: metricsLive, compact: true, vertical: true,
                                          inspect: { inspect(.agents($0)) }, inspectResources: { inspect(.appResources) }, inspectRange: inspectRange)
                        Button(action: showCheckStatus) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(checkSummary.headline).font(.system(size: 14, weight: .semibold, design: .monospaced)).foregroundStyle(.yellow)
                                Text("Reason & next step ↗").font(.system(size: 12, design: .monospaced)).foregroundStyle(Self.muted)
                            }.fixedSize(horizontal: false, vertical: true)
                        }.buttonStyle(.plain).help(checkSummary.explanation)
                        if let finding = openFindings.first {
                            Button { inspect(.findings(finding.id)) } label: {
                                Text("LATEST ↗ \(finding.title)").font(.system(size: 13, design: .monospaced))
                                    .foregroundStyle(Self.pink).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                            }.buttonStyle(.plain).help("\(finding.whatHappened)\n\(finding.whyFlagged)")
                                .accessibilityLabel("Inspect latest finding: \(finding.title)")
                        } else {
                            Text("No findings does not establish safety.").font(.system(size: 12, design: .monospaced)).foregroundStyle(Self.muted)
                        }
                    }.padding(.bottom, 4)
                }
                if size == .expanded {
                    Button(action: resize) {
                        Label("Shrink", systemImage: "arrow.down.right.and.arrow.up.left")
                    }.buttonStyle(.plain).font(.system(size: 16, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Self.cyan).accessibilityLabel("Shrink overlay")
                }
                fileActivityButton(fontSize: 16)
                Button(action: dashboard) {
                    Label("Dashboard", systemImage: "arrow.up.right")
                        .font(.system(size: 18, weight: .semibold, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 7).foregroundStyle(Self.cyan)
                }.buttonStyle(.plain)
            }.frame(width: 190, height: 694, alignment: .topLeading).offset(x: 69, y: 245)
        }.frame(width: 360, height: 1080)
            .foregroundStyle(Color.white.opacity(0.94))
    }

    private func verticalControl(_ title: String, symbol: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.system(size: 16, weight: .semibold))
                .frame(width: 23, height: 26).contentShape(Rectangle())
        }.buttonStyle(.plain).foregroundStyle(title == "Close overlay" ? Self.pink : Self.cyan)
            .accessibilityLabel(title).help(title)
    }

    private func verticalMetric(_ title: String, value: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(.system(size: 12, weight: .semibold, design: .monospaced)).foregroundStyle(Self.muted)
                Text(value).font(.system(size: 25, weight: .semibold, design: .monospaced)).foregroundStyle(color).monospacedDigit()
                    .lineLimit(1).minimumScaleFactor(0.7)
            }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
        }.buttonStyle(.plain).accessibilityLabel("\(title): \(value). Inspect details")
    }

    // The artwork's square expands; only the expanded overlay needs a Shrink action.
    @ViewBuilder private var shrinkButton: some View {
        if size == .expanded {
            Button(action: resize) {
                Label("Shrink", systemImage: "arrow.down.right.and.arrow.up.left")
                    .font(.system(size: compact ? 23 : 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Self.cyan)
                    .padding(.horizontal, 12).padding(.vertical, compact ? 4 : 3)
                    .background(Self.cyan.opacity(0.07))
                    .overlay(CutCornerWell(cut: 5).stroke(Self.cyan.opacity(0.65), lineWidth: 0.7))
            }.buttonStyle(.plain)
                .accessibilityLabel("Shrink overlay")
                .help("Return to the small, compact overlay")
        }
    }

    private func metric(_ title: String, value: String, note: String, color: Color, destination: DashboardMetric) -> some View {
        Button { inspect(destination == .reporting ? .coverage(.all) : destination.destination) } label: {
          VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 8, weight: .semibold, design: .monospaced)).tracking(1).foregroundStyle(Self.muted)
            Text(value).font(.system(size: 22, weight: .medium, design: .monospaced)).monospacedDigit()
                .foregroundStyle(color).shadow(color: color.opacity(0.4), radius: 7)
            Text(note).font(.system(size: 8, design: .monospaced)).foregroundStyle(Self.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
          .contentShape(Rectangle())
        }.buttonStyle(.plain).help(destination == .reporting ? checkSummary.catalogExplanation : "Open \(title) in the existing dashboard")
            .accessibilityLabel("\(title): \(value). Inspect details")
    }

    private var investigationMenu: some View {
        Menu("INSPECT") {
            Button("Take one snapshot", action: snapshot).disabled(sampling)
            if let finding = openFindings.first {
                Button("Latest finding: \(finding.title)") { inspect(.findings(finding.id)) }
            }
            ForEach(Array((view?.events ?? []).prefix(3))) { event in
                Button("\(event.observation.eventClass.rawValue): \(event.observation.component)") { inspect(.event(event.id)) }
            }
            Divider()
            Button("Configure tripwires…") { inspect(.tripwires) }
            Button("Recorded tripwire alerts") { inspect(.tripwireAlerts) }
            ForEach(sensors) { sensor in
                Button("\(sensor.descriptor.name): \(sensor.state.rawValue)") { inspect(.coverage(.sensor(sensor.id))) }
            }
        }.menuStyle(.borderlessButton)
            .font(.system(size: 9, weight: .semibold, design: .monospaced)).foregroundStyle(Self.cyan)
            .frame(width: 70).help("Inspect individual sensors and the latest finding/evidence")
    }

    private func actionButton(_ title: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.system(size: 8, weight: .bold, design: .monospaced)).tracking(1)
                .foregroundStyle(color).padding(.horizontal, 10).padding(.vertical, 8)
                .background(color.opacity(0.07))
                .overlay(CutCornerWell(cut: 5).stroke(color.opacity(0.65), lineWidth: 0.7))
        }.buttonStyle(.plain)
    }

    private func artworkButton(_ label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Color.white.opacity(0.001).frame(width: 37, height: 33).contentShape(Rectangle()) }
            .buttonStyle(.plain).help(label).accessibilityLabel(label)
    }
}

/// Follows the empty opening of the tall artwork, extending just beneath its
/// inner border so the glass remains continuous around the stepped sides.
private struct VerticalOverlayWell: Shape {
    func path(in rect: CGRect) -> Path {
        let vertices: [CGPoint] = [
            CGPoint(x: 130, y: 187), CGPoint(x: 228, y: 187),
            CGPoint(x: 274, y: 231), CGPoint(x: 270, y: 289),
            CGPoint(x: 270, y: 450), CGPoint(x: 284, y: 466),
            CGPoint(x: 284, y: 876), CGPoint(x: 260, y: 903),
            CGPoint(x: 260, y: 959), CGPoint(x: 161, y: 959),
            CGPoint(x: 149, y: 951), CGPoint(x: 82, y: 951),
            CGPoint(x: 55, y: 924), CGPoint(x: 55, y: 865),
            CGPoint(x: 66, y: 848), CGPoint(x: 66, y: 735),
            CGPoint(x: 50, y: 717), CGPoint(x: 50, y: 620),
            CGPoint(x: 56, y: 610), CGPoint(x: 56, y: 370),
            CGPoint(x: 51, y: 361), CGPoint(x: 51, y: 231),
            CGPoint(x: 68, y: 211)
        ]
        return Path { path in
            path.addLines(vertices.map { CGPoint(x: rect.minX + $0.x * rect.width / 360, y: rect.minY + $0.y * rect.height / 1080) })
            path.closeSubpath()
        }
    }
}

private struct CutCornerWell: Shape {
    var cut: CGFloat = 31
    func path(in rect: CGRect) -> Path {
        Path { path in
            path.move(to: CGPoint(x: rect.minX + cut, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - cut, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + cut))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - cut))
            path.addLine(to: CGPoint(x: rect.maxX - cut, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX + cut, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - cut))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + cut))
            path.closeSubpath()
        }
    }
}

/// Fits under the inner rim of the supplied square widget without filling the
/// transparent canvas or its projecting fuse/sparks.
private struct MiniOverlayWell: Shape {
    func path(in rect: CGRect) -> Path {
        let vertices: [CGPoint] = [
            CGPoint(x: 240, y: 455), CGPoint(x: 997, y: 455),
            CGPoint(x: 1065, y: 520), CGPoint(x: 1065, y: 678),
            CGPoint(x: 1074, y: 717), CGPoint(x: 1074, y: 1012),
            CGPoint(x: 980, y: 1105), CGPoint(x: 533, y: 1105),
            CGPoint(x: 495, y: 1074), CGPoint(x: 246, y: 1074),
            CGPoint(x: 157, y: 1008), CGPoint(x: 157, y: 869),
            CGPoint(x: 145, y: 843), CGPoint(x: 145, y: 595),
            CGPoint(x: 178, y: 563), CGPoint(x: 178, y: 511)
        ]
        return Path { path in
            path.addLines(vertices.map { CGPoint(x: rect.minX + $0.x * rect.width / 1308, y: rect.minY + $0.y * rect.height / 1203) })
            path.closeSubpath()
        }
    }
}
