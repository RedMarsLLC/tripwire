import AppKit
import SwiftUI
import TripWireCore

struct MetricSeries {
    var points: [MetricPoint]
    var color: Color
}

/// The gesture belongs only to the plot, never the overlay's native drag header.
struct SelectableMetricChart: View {
    var series: [MetricSeries]
    var maximum: Double
    var markers: [AgentReceipt] = []
    var live: Bool
    var focus: MetricFocus
    var capture: () -> MetricCapture
    var inspect: (MetricInspection) -> Void
    private struct Selection {
        var capture: MetricCapture
        var series: [MetricSeries]
        var markers: [AgentReceipt]
        var maximum: Double
        var start: Double
        var end: Double
    }
    @State private var selection: Selection?

    var body: some View {
        GeometryReader { geometry in
            let width = max(1, geometry.size.width)
            let active = selection?.series ?? series
            ZStack(alignment: .topLeading) {
                ForEach(Array(active.enumerated()), id: \.offset) { index, line in
                    RetroTrace(points: line.points, now: selection?.capture.date ?? (live ? Date() : capture().date), maximum: selection?.maximum ?? maximum,
                               color: line.color, markers: index == 0 ? (selection?.markers ?? markers) : [],
                               live: selection == nil && live, drawsBackground: index == 0)
                }
                if let selection {
                    let left = min(selection.start, selection.end), right = max(selection.start, selection.end)
                    Rectangle().fill(Color.cyan.opacity(0.22)).frame(width: max(2, right - left)).offset(x: left)
                    Rectangle().fill(Color.cyan).frame(width: 1).offset(x: left)
                    Rectangle().fill(Color.cyan).frame(width: 1).offset(x: right)
                }
            }
            .contentShape(Rectangle())
            .gesture(DragGesture(minimumDistance: 0).onChanged { value in
                if selection == nil {
                    selection = Selection(capture: capture(), series: series, markers: markers, maximum: maximum,
                                          start: min(width, max(0, value.startLocation.x)), end: min(width, max(0, value.location.x)))
                } else { selection?.end = min(width, max(0, value.location.x)) }
            }.onEnded { value in
                guard let selected = selection else { return }
                let interval = MetricSelection.interval(from: selected.start, to: value.location.x, width: width, endingAt: selected.capture.date)
                selection = nil
                inspect(MetricInspection(focus: focus, interval: interval, capture: selected.capture))
            })
            .onExitCommand { selection = nil }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("\(focus.title) chart. Click a spike or drag a time range to investigate")
            .accessibilityAddTraits(.isButton)
            .accessibilityAction {
                let snapshot = capture()
                inspect(MetricInspection(focus: focus, interval: DateInterval(start: snapshot.date.addingTimeInterval(-60), end: snapshot.date), capture: snapshot))
            }
            .help("Click a spike to inspect nearby samples, or drag across a range. The chart freezes while selecting. Release to open the investigation; Escape cancels.")
        }
    }
}
