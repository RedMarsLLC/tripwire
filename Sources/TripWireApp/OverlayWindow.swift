import AppKit
import SwiftUI

enum OverlaySize: String {
    case compact, expanded
    static let preferenceKey = "overlay.presentationSize"
    var width: CGFloat { self == .compact ? 480 : 1000 }
    func width(for orientation: OverlayOrientation) -> CGFloat {
        switch orientation {
        case .horizontal: return width
        case .vertical: return self == .compact ? 260 : 340
        case .mini: return self == .compact ? 300 : 440
        }
    }
    var next: Self { self == .compact ? .expanded : .compact }
    static func saved(in defaults: UserDefaults) -> Self {
        defaults.string(forKey: preferenceKey).flatMap(Self.init(rawValue:)) ?? .compact
    }
}

enum OverlayOrientation: String, CaseIterable {
    case horizontal, vertical, mini
    static let preferenceKey = "overlay.orientation"
    var canvasWidth: CGFloat { self == .horizontal ? OverlayLayout.canvasWidth : 360 }
    var aspect: CGFloat {
        switch self {
        case .horizontal: return OverlayLayout.aspect
        case .vertical: return 3
        case .mini: return CGFloat(1203) / 1308
        }
    }
    /// Frame outline in the original, top-left artwork coordinates. Transparent
    /// canvas padding and the tall frame's projecting sparks are not keepaways.
    /// Keep the complete artwork when floating; only edge placement may let its
    /// glow/sparks extend beyond the usable desktop.
    var placementBounds: CGRect {
        if self == .mini {
            return CGRect(x: 64, y: 189, width: 1079, height: 988)
                .applying(CGAffineTransform(scaleX: canvasWidth / 1308, y: canvasWidth / 1308))
        }
        let pixels = self == .vertical
            ? CGRect(x: 23, y: 74, width: 653, height: 1950)
            : CGRect(x: 34, y: 82, width: 1601, height: 777)
        let scale = canvasWidth / (self == .vertical ? 724 : 1671)
        return pixels.applying(CGAffineTransform(scaleX: scale, y: scale))
    }
    var header: CGRect {
        switch self {
        case .horizontal: return OverlayLayout.header
        case .vertical: return CGRect(x: 28, y: 65, width: 255, height: 112)
        case .mini: return CGRect(x: 22, y: 77, width: 187, height: 41)
        }
    }
    static func saved(in defaults: UserDefaults) -> Self {
        defaults.string(forKey: preferenceKey).flatMap(Self.init(rawValue:)) ?? .horizontal
    }
}

enum OverlayEdge { case left, right, top }

/// All artwork and hit targets use this canvas, then scale together to fit a display.
enum OverlayLayout {
    static let aspect = CGFloat(941) / 1671
    static let canvasWidth: CGFloat = 1000
    static let header = CGRect(x: 40, y: 106, width: 920, height: 122)

    static func visibleBounds(of frame: CGRect, orientation: OverlayOrientation = .horizontal) -> CGRect {
        let scale = frame.width / orientation.canvasWidth
        let outline = orientation.placementBounds
        return CGRect(x: frame.minX + outline.minX * scale,
                      y: frame.maxY - outline.maxY * scale,
                      width: outline.width * scale, height: outline.height * scale)
    }

    static func edge(of frame: CGRect, visibleFrame: CGRect, orientation: OverlayOrientation = .horizontal) -> OverlayEdge? {
        let visible = visibleBounds(of: frame, orientation: orientation)
        if abs(visible.minX - visibleFrame.minX) < 1 { return .left }
        if abs(visible.maxX - visibleFrame.maxX) < 1 { return .right }
        return nil
    }

    static func frame(preferredWidth: CGFloat, visibleFrame: CGRect, previous: CGRect? = nil,
                      orientation: OverlayOrientation = .horizontal, edge: OverlayEdge? = nil) -> CGRect {
        let usable = visibleFrame
        let outline = orientation.placementBounds
        let width = floor(min(preferredWidth, usable.width * orientation.canvasWidth / outline.width,
                              usable.height * orientation.canvasWidth / outline.height))
        let scale = width / orientation.canvasWidth
        let size = CGSize(width: width, height: width * orientation.aspect)
        let drawnSize = CGSize(width: outline.width * scale, height: outline.height * scale)
        // Anchor the visible outline, not the transparent canvas. This also
        // preserves the visible top-left corner when the user changes size.
        var origin = previous.map { visibleBounds(of: $0, orientation: orientation) }
            .map { CGPoint(x: $0.minX, y: $0.maxY - drawnSize.height) }
            ?? (orientation != .horizontal
                ? CGPoint(x: usable.maxX - drawnSize.width, y: usable.maxY - drawnSize.height)
                : CGPoint(x: usable.midX - drawnSize.width / 2, y: usable.midY - drawnSize.height / 2))
        switch edge {
        case .left: origin.x = usable.minX
        case .right: origin.x = usable.maxX - drawnSize.width
        case .top: origin.y = usable.maxY - drawnSize.height
        case nil: break
        }
        origin.x = max(usable.minX, min(origin.x, usable.maxX - drawnSize.width))
        origin.y = max(usable.minY, min(origin.y, usable.maxY - drawnSize.height))
        return CGRect(x: origin.x - outline.minX * scale,
                      y: origin.y - (orientation.canvasWidth * orientation.aspect - outline.maxY) * scale,
                      width: size.width, height: size.height)
    }
}

/// Own the native window instead of changing the frame/style of a SwiftUI Scene
/// while SwiftUI is also restoring and sizing it.
@MainActor final class OverlayWindowController: NSObject, ObservableObject, NSWindowDelegate {
    private var panel: OverlayPanel?
    private let viewport = OverlayViewport()
    private let metrics = OverlayMetricsModel()
    private var size = OverlaySize.saved(in: .standard)
    private var orientation = OverlayOrientation.saved(in: .standard)
    private var previousFrames: [OverlayOrientation: CGRect] = [:]

    override init() {
        super.init()
        NotificationCenter.default.addObserver(
            self, selector: #selector(displaysChanged),
            name: NSApplication.didChangeScreenParametersNotification, object: nil
        )
    }

    deinit { NotificationCenter.default.removeObserver(self) }

    func show(model: DashboardModel, dashboard: @escaping () -> Void) {
        metrics.configure(storeURL: model.storeURL)
        if let panel {
            fitToScreen()
            if panel.isMiniaturized { panel.deminiaturize(nil) }
            panel.makeKeyAndOrderFront(nil)
            metrics.setVisible(true)
            return
        }
        guard let screen = NSApp.keyWindow?.screen ?? NSScreen.main ?? NSScreen.screens.first else { return }
        let frame = OverlayLayout.frame(preferredWidth: size.width(for: orientation), visibleFrame: screen.visibleFrame, orientation: orientation)
        viewport.width = frame.width
        viewport.size = size
        viewport.orientation = orientation
        let panel = OverlayPanel(contentRect: frame, styleMask: [.borderless, .miniaturizable, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.title = "TripWire Watchdog"
        panel.isReleasedWhenClosed = false
        panel.isRestorable = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.hidesOnDeactivate = false
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .canJoinAllApplications]
        panel.isMovableByWindowBackground = false
        panel.delegate = self

        let content = OverlayContent(
            model: model, viewport: viewport, metrics: metrics, dashboard: { [weak self] in
                // Make room to read the investigation. The Overlay button brings
                // this same panel back at its existing position.
                self?.metrics.setVisible(false)
                self?.panel?.orderOut(nil)
                dashboard()
            },
            minimize: { [weak self] in self?.panel?.miniaturize(nil) },
            expand: { [weak self] in self?.setSize(.expanded) },
            resize: { [weak self] in self?.toggleSize() },
            changeOrientation: { [weak self] in self?.setOrientation($0) },
            moveToEdge: { [weak self] in self?.fitToScreen(edge: $0) },
            close: { [weak self] in self?.panel?.close() }
        )
        let hosting = NSHostingView(rootView: content)
        // The artwork's unscaled intrinsic width must never resize the panel.
        hosting.sizingOptions = []
        let surface = OverlaySurface(frame: CGRect(origin: .zero, size: frame.size), hosting: hosting, orientation: orientation)
        panel.didFinishDragging = { [weak self] in self?.fitToScreen() }
        panel.contentView = surface
        self.panel = panel
        panel.setFrame(frame, display: true)
        panel.makeKeyAndOrderFront(nil)
        metrics.setVisible(true)
    }

    private func toggleSize() {
        setSize(size.next)
    }

    private func setSize(_ newSize: OverlaySize) {
        guard size != newSize else { return }
        size = newSize
        UserDefaults.standard.set(size.rawValue, forKey: OverlaySize.preferenceKey)
        fitToScreen()
    }

    private func setOrientation(_ newOrientation: OverlayOrientation) {
        guard orientation != newOrientation else { return }
        if let panel { previousFrames[orientation] = panel.frame }
        orientation = newOrientation
        // Selecting Super compact should always produce the small widget, even
        // if the previous horizontal or vertical presentation was expanded.
        if newOrientation == .mini {
            size = .compact
            UserDefaults.standard.set(size.rawValue, forKey: OverlaySize.preferenceKey)
        }
        UserDefaults.standard.set(orientation.rawValue, forKey: OverlayOrientation.preferenceKey)
        // Restore a dragged position when returning to an orientation. The first
        // vertical presentation starts at the right edge, clear of the Dock.
        fitToScreen(restoringOrientation: true)
    }

    private func fitToScreen(edge: OverlayEdge? = nil, restoringOrientation: Bool = false) {
        guard let panel, let screen = panel.screen ?? NSScreen.main ?? NSScreen.screens.first else { return }
        let frame = OverlayLayout.frame(
            preferredWidth: size.width(for: orientation),
            visibleFrame: screen.visibleFrame,
            previous: restoringOrientation ? previousFrames[orientation] : panel.frame,
            orientation: orientation, edge: edge ?? (!restoringOrientation
                ? OverlayLayout.edge(of: panel.frame, visibleFrame: screen.visibleFrame, orientation: orientation) : nil)
        )
        viewport.width = frame.width
        viewport.size = size
        viewport.orientation = orientation
        (panel.contentView as? OverlaySurface)?.orientation = orientation
        if panel.frame != frame { panel.setFrame(frame, display: true) }
    }

    @objc private func displaysChanged() {
        // Fit only after release, never in the middle of the pointer's movement.
        if panel?.isDragging != true { fitToScreen() }
    }

    func windowDidChangeScreen(_ notification: Notification) { displaysChanged() }
    func windowDidMiniaturize(_ notification: Notification) { metrics.setVisible(false) }
    func windowDidDeminiaturize(_ notification: Notification) { metrics.setVisible(true) }
    func windowWillClose(_ notification: Notification) { metrics.setVisible(false) }
}

@MainActor private final class OverlayViewport: ObservableObject {
    @Published var width: CGFloat = OverlaySize.compact.width
    @Published var size: OverlaySize = .compact
    @Published var orientation: OverlayOrientation = .horizontal
}

private struct OverlayContent: View {
    @ObservedObject var model: DashboardModel
    @ObservedObject var viewport: OverlayViewport
    @ObservedObject var metrics: OverlayMetricsModel
    var dashboard: () -> Void
    var minimize: () -> Void
    var expand: () -> Void
    var resize: () -> Void
    var changeOrientation: (OverlayOrientation) -> Void
    var moveToEdge: (OverlayEdge) -> Void
    var close: () -> Void
    private let timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        CyberOverlayPanel(
            view: model.view, sensors: model.sensors, error: model.error, sampling: model.sampling, running: model.running,
            checkSummary: model.checkSummary,
            compact: viewport.width < 800,
            size: viewport.size, orientation: viewport.orientation, resources: metrics.resources, appResources: metrics.appResources, hooks: metrics.hooks,
            hookHistory: metrics.hookHistory, metricsLive: metrics.isSampling && metrics.isVisible,
            snapshot: { model.begin(once: true) }, startMonitoring: { model.begin(once: false) }, dashboard: dashboard,
            inspect: { route in
                model.appResourceSnapshot = metrics.appResources
                model.route = route; dashboard()
            },
            inspectRange: { inspection in
                model.metricInspection = inspection
                model.route = .spike
                dashboard()
            },
            minimize: minimize, expand: expand, resize: resize, changeOrientation: changeOrientation, moveToEdge: moveToEdge, close: close
        )
        .scaleEffect(viewport.width / viewport.orientation.canvasWidth, anchor: .topLeading)
        .frame(width: viewport.width, height: viewport.width * viewport.orientation.aspect, alignment: .topLeading)
        .preferredColorScheme(.dark)
        .onReceive(timer) { _ in model.refreshInBackground() }
    }
}

class OverlayPanel: NSPanel {
    private struct Drag {
        var pointer: CGPoint
        var origin: CGPoint
    }
    private var drag: Drag?
    var didFinishDragging: (() -> Void)?
    var isDragging: Bool { drag != nil }
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func constrainFrameRect(_ frameRect: NSRect, to screen: NSScreen?) -> NSRect {
        // OverlayLayout keeps the visible frame and controls on the desktop.
        // AppKit must not push the invisible artwork margin below the menu bar.
        frameRect
    }

    override func sendEvent(_ event: NSEvent) {
        // Handle only this panel's header. Routing at the window avoids SwiftUI
        // hit testing swallowing a drag; other controls keep normal dispatch.
        switch event.type {
        case .leftMouseDown:
            if let surface = contentView as? OverlaySurface,
               surface.header.frame.contains(surface.convert(event.locationInWindow, from: nil)) {
                drag = Drag(pointer: convertPoint(toScreen: event.locationInWindow), origin: frame.origin)
                NSCursor.closedHand.push()
                return
            }
        case .leftMouseDragged:
            if drag != nil { moveWithPointer(event); return }
        case .leftMouseUp:
            if drag != nil {
                moveWithPointer(event)
                endDrag()
                didFinishDragging?()
                return
            }
        default:
            break
        }
        super.sendEvent(event)
    }

    private func moveWithPointer(_ event: NSEvent) {
        guard let drag else { return }
        let pointer = convertPoint(toScreen: event.locationInWindow)
        setFrameOrigin(CGPoint(
            x: drag.origin.x + pointer.x - drag.pointer.x,
            y: drag.origin.y + pointer.y - drag.pointer.y
        ))
    }

    private func endDrag() {
        guard drag != nil else { return }
        drag = nil
        NSCursor.pop()
    }

    override func close() {
        endDrag()
        super.close()
    }
}

/// An AppKit sibling supplies the header's cursor and first-click behavior.
/// OverlayPanel owns the full drag sequence, independently of hosted content.
final class OverlaySurface: NSView {
    let header = OverlayHeaderDragView()
    private let hosting: NSView
    var orientation: OverlayOrientation { didSet { positionHeader() } }
    override var isFlipped: Bool { true }

    init(frame: CGRect, hosting: NSView, orientation: OverlayOrientation = .horizontal) {
        self.hosting = hosting
        self.orientation = orientation
        super.init(frame: frame)
        hosting.frame = bounds
        hosting.autoresizingMask = [.width, .height]
        addSubview(hosting)
        addSubview(header, positioned: .above, relativeTo: hosting)
        // Give the transparent panel a native hit surface over the artwork.
        header.wantsLayer = true
        header.layer?.isOpaque = false
        // A fully clear layer in a borderless window can be skipped by the
        // WindowServer before AppKit hit testing. Keep a barely visible native
        // surface over the illustrated header, independent of SwiftUI redraws.
        header.layer?.backgroundColor = NSColor.white.withAlphaComponent(0.01).cgColor
        header.toolTip = "Drag to move the overlay"
        header.setAccessibilityElement(true)
        header.setAccessibilityRole(.group)
        header.setAccessibilityLabel("Drag TripWire overlay")
        positionHeader()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func layout() {
        super.layout()
        positionHeader()
    }

    private func positionHeader() {
        let scale = bounds.width / orientation.canvasWidth
        header.frame = orientation.header.applying(CGAffineTransform(scaleX: scale, y: scale))
    }
}

final class OverlayHeaderDragView: NSView {
    override var mouseDownCanMoveWindow: Bool { false }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    override func resetCursorRects() { addCursorRect(bounds, cursor: .openHand) }
}
