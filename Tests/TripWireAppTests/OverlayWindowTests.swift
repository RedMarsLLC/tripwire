import AppKit
import SwiftUI
import XCTest
@testable import TripWireApp

final class OverlayWindowTests: XCTestCase {
    func testSuperCompactGeometryAndPreference() {
        let suite = "tripwire-mini-test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("mini", forKey: OverlayOrientation.preferenceKey)
        XCTAssertEqual(OverlayOrientation.saved(in: defaults), .mini)
        let screen = CGRect(x: -1440, y: 24, width: 1440, height: 876)
        let small = OverlayLayout.frame(preferredWidth: OverlaySize.compact.width(for: .mini), visibleFrame: screen, orientation: .mini)
        XCTAssertEqual(small.width, 300)
        XCTAssertLessThan(small.height, 280)
        let large = OverlayLayout.frame(preferredWidth: OverlaySize.expanded.width(for: .mini), visibleFrame: screen, previous: small, orientation: .mini, edge: .right)
        XCTAssertGreaterThan(large.width, small.width)
        let shrunk = OverlayLayout.frame(preferredWidth: OverlaySize.compact.width(for: .mini), visibleFrame: screen, previous: large, orientation: .mini, edge: .right)
        XCTAssertEqual(shrunk.width, small.width)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: shrunk, orientation: .mini).maxX, screen.maxX, accuracy: 0.001)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: shrunk, orientation: .mini).maxY, screen.maxY, accuracy: 0.001)
    }

    func testVerticalFitsVisibleScreenAndEitherEdge() {
        for visible in [CGRect(x: 0, y: 40, width: 1440, height: 860),
                        CGRect(x: -1280, y: -200, width: 1280, height: 520)] {
            for size in [OverlaySize.compact, .expanded] {
                let width = size.width(for: .vertical)
                let right = OverlayLayout.frame(preferredWidth: width, visibleFrame: visible, orientation: .vertical)
                let rightOutline = OverlayLayout.visibleBounds(of: right, orientation: .vertical)
                XCTAssertTrue(visible.insetBy(dx: -0.001, dy: -0.001).contains(rightOutline))
                XCTAssertEqual(right.height / right.width, 3, accuracy: 0.001)
                XCTAssertEqual(rightOutline.maxX, visible.maxX, accuracy: 0.001)
                XCTAssertEqual(rightOutline.maxY, visible.maxY, accuracy: 0.001)
                let left = OverlayLayout.frame(preferredWidth: width, visibleFrame: visible, previous: right, orientation: .vertical, edge: .left)
                let leftOutline = OverlayLayout.visibleBounds(of: left, orientation: .vertical)
                XCTAssertEqual(leftOutline.minX, visible.minX, accuracy: 0.001)
                XCTAssertEqual(leftOutline.maxY, rightOutline.maxY, accuracy: 0.001)
                XCTAssertTrue(visible.insetBy(dx: -0.001, dy: -0.001).contains(leftOutline))
                let smaller = OverlayLayout.frame(preferredWidth: 200, visibleFrame: visible, previous: right, orientation: .vertical,
                                                  edge: OverlayLayout.edge(of: right, visibleFrame: visible, orientation: .vertical))
                XCTAssertEqual(OverlayLayout.visibleBounds(of: smaller, orientation: .vertical).maxX, rightOutline.maxX, accuracy: 0.001)
            }
        }
    }

    func testOrientationPreferenceIsIndependentFromSizeAndInvalidValuesFallBack() throws {
        let suite = "tripwire-overlay-orientation-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertEqual(OverlayOrientation.saved(in: defaults), .horizontal)
        defaults.set("vertical", forKey: OverlayOrientation.preferenceKey)
        XCTAssertEqual(OverlayOrientation.saved(in: defaults), .vertical)
        XCTAssertEqual(OverlaySize.saved(in: defaults), .compact)
        defaults.set("obsolete", forKey: OverlayOrientation.preferenceKey)
        XCTAssertEqual(OverlayOrientation.saved(in: defaults), .horizontal)
    }

    func testVerticalPreservesDraggedPositionAndRecoversOffscreenPosition() {
        let screen = CGRect(x: 0, y: 40, width: 1440, height: 950)
        let dragged = CGRect(x: 145, y: 120, width: 260, height: 780)
        XCTAssertNil(OverlayLayout.edge(of: dragged, visibleFrame: screen, orientation: .vertical))
        let fitted = OverlayLayout.frame(preferredWidth: 260, visibleFrame: screen, previous: dragged, orientation: .vertical)
        XCTAssertEqual(fitted.minX, dragged.minX, accuracy: 0.001)
        XCTAssertEqual(fitted.minY, dragged.minY, accuracy: 0.001)
        XCTAssertEqual(fitted.size, dragged.size)
        let lost = CGRect(x: -1500, y: -500, width: 340, height: 1020)
        let recovered = OverlayLayout.frame(preferredWidth: 340, visibleFrame: screen, previous: lost, orientation: .vertical)
        XCTAssertTrue(screen.insetBy(dx: -0.001, dy: -0.001).contains(OverlayLayout.visibleBounds(of: recovered, orientation: .vertical)))
    }

    func testOverlayFitsNarrowAndShortScreens() {
        for visible in [
            CGRect(x: 0, y: 38, width: 816, height: 1060),
            CGRect(x: 0, y: 80, width: 1440, height: 440),
            CGRect(x: -1280, y: -200, width: 1280, height: 720)
        ] {
            for width: CGFloat in [OverlaySize.compact.width, OverlaySize.expanded.width] {
                let frame = OverlayLayout.frame(preferredWidth: width, visibleFrame: visible)
                let outline = OverlayLayout.visibleBounds(of: frame)
                XCTAssertTrue(visible.insetBy(dx: -0.001, dy: -0.001).contains(outline))
                XCTAssertLessThanOrEqual(frame.width, width)
                XCTAssertEqual(frame.height / frame.width, CGFloat(941) / 1671, accuracy: 0.0001)
                XCTAssertEqual(outline.midX, visible.midX, accuracy: 0.001)
                XCTAssertEqual(outline.midY, visible.midY, accuracy: 0.001)
            }
        }
    }

    func testOverlayDefaultsToCompactAndRemembersTheChosenSize() throws {
        let suite = "tripwire-overlay-size-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertEqual(OverlaySize.saved(in: defaults), .compact)
        defaults.set(OverlaySize.expanded.rawValue, forKey: OverlaySize.preferenceKey)
        XCTAssertEqual(OverlaySize.saved(in: defaults), .expanded)
        defaults.set(OverlaySize.saved(in: defaults).next.rawValue, forKey: OverlaySize.preferenceKey)
        XCTAssertEqual(OverlaySize.saved(in: defaults), .compact)
        defaults.set("obsolete-size", forKey: OverlaySize.preferenceKey)
        XCTAssertEqual(OverlaySize.saved(in: defaults), .compact)
    }

    func testCompactAndExpandedKeepPositionAndFitOnScreen() {
        let screen = CGRect(x: 0, y: 40, width: 1440, height: 860)
        let compact = OverlayLayout.frame(preferredWidth: OverlaySize.compact.width, visibleFrame: screen)
        XCTAssertEqual(compact.width, 480)
        XCTAssertLessThan(compact.height, 271)
        let expanded = OverlayLayout.frame(preferredWidth: OverlaySize.expanded.width, visibleFrame: screen, previous: compact)
        let restored = OverlayLayout.frame(preferredWidth: OverlaySize.compact.width, visibleFrame: screen, previous: expanded)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: restored).maxY, OverlayLayout.visibleBounds(of: expanded).maxY, accuracy: 0.001)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: restored).minX, OverlayLayout.visibleBounds(of: expanded).minX, accuracy: 0.001)
        XCTAssertTrue(screen.contains(OverlayLayout.visibleBounds(of: restored)))
        XCTAssertLessThan(compact.width * compact.height, expanded.width * expanded.height / 4)
    }

    func testOffscreenPositionAndExpansionAreRecovered() {
        let screen = CGRect(x: -1280, y: 60, width: 1280, height: 700)
        for previous in [
            CGRect(x: 1200, y: 200, width: 1000, height: 563),
            CGRect(x: -2000, y: -800, width: 1800, height: 1014),
            CGRect(x: -1040, y: 84, width: 1000, height: 563)
        ] {
            let fitted = OverlayLayout.frame(preferredWidth: 1200, visibleFrame: screen, previous: previous)
            XCTAssertTrue(screen.insetBy(dx: -0.001, dy: -0.001).contains(OverlayLayout.visibleBounds(of: fitted)))
        }
    }

    func testFitPreservesAUserChosenPosition() {
        let screen = CGRect(x: 0, y: 40, width: 1920, height: 1010)
        let chosen = CGRect(x: 164, y: 190, width: 1000, height: 1000 * OverlayLayout.aspect)
        let fitted = OverlayLayout.frame(preferredWidth: 1000, visibleFrame: screen, previous: chosen)
        XCTAssertEqual(fitted.minX, chosen.minX, accuracy: 0.001)
        XCTAssertEqual(fitted.minY, chosen.minY, accuracy: 0.001)
        let expanded = OverlayLayout.frame(preferredWidth: 1200, visibleFrame: screen, previous: chosen)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: expanded).minX, OverlayLayout.visibleBounds(of: chosen).minX, accuracy: 0.001)
        XCTAssertEqual(OverlayLayout.visibleBounds(of: expanded).maxY, OverlayLayout.visibleBounds(of: chosen).maxY, accuracy: 0.001)
    }

    func testDraggingToTopCornersDoesNotBounceAwayFromTheVisibleEdge() {
        let screen = CGRect(x: -1440, y: 60, width: 1440, height: 840)
        for orientation in OverlayOrientation.allCases {
            for size in [OverlaySize.compact, .expanded] {
                for x: CGFloat in [-3000, 1000] {
                    let dragged = CGRect(x: x, y: 1000, width: size.width(for: orientation), height: size.width(for: orientation) * orientation.aspect)
                    let fitted = OverlayLayout.frame(preferredWidth: dragged.width, visibleFrame: screen, previous: dragged, orientation: orientation)
                    let outline = OverlayLayout.visibleBounds(of: fitted, orientation: orientation)
                    XCTAssertEqual(outline.maxY, screen.maxY, accuracy: 0.001)
                    XCTAssertEqual(x < screen.minX ? outline.minX : outline.maxX, x < screen.minX ? screen.minX : screen.maxX, accuracy: 0.001)
                    XCTAssertGreaterThan(fitted.maxY, screen.maxY, "Transparent top padding must be allowed outside the usable desktop")
                    let fittedAgain = OverlayLayout.frame(preferredWidth: dragged.width, visibleFrame: screen, previous: fitted, orientation: orientation)
                    XCTAssertEqual(fittedAgain.minX, fitted.minX, accuracy: 0.001)
                    XCTAssertEqual(fittedAgain.minY, fitted.minY, accuracy: 0.001)
                    let movedToTop = OverlayLayout.frame(preferredWidth: dragged.width, visibleFrame: screen,
                        previous: fitted.offsetBy(dx: 0, dy: -50), orientation: orientation, edge: .top)
                    XCTAssertEqual(OverlayLayout.visibleBounds(of: movedToTop, orientation: orientation).maxY, screen.maxY, accuracy: 0.001)
                }
            }
        }
    }

    @MainActor func testNativePanelDoesNotReapplyTransparentCanvasKeepaway() {
        _ = NSApplication.shared
        let panel = OverlayPanel(contentRect: CGRect(x: 0, y: 0, width: 260, height: 780), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isReleasedWhenClosed = false
        defer { panel.close() }
        let desktop = NSScreen.main?.visibleFrame ?? CGRect(x: 0, y: 80, width: 1440, height: 820)
        let requested = OverlayLayout.frame(preferredWidth: 260, visibleFrame: desktop, orientation: .vertical)
        XCTAssertEqual(panel.constrainFrameRect(requested, to: NSScreen.main), requested)
        panel.setFrame(requested, display: false)
        // AppKit rounds window origins to whole points; that is not a keepaway.
        XCTAssertEqual(panel.frame.minX, requested.minX, accuracy: 1)
        XCTAssertEqual(panel.frame.maxY, requested.maxY, accuracy: 1)
        let outline = OverlayLayout.visibleBounds(of: panel.frame, orientation: .vertical)
        XCTAssertEqual(outline.maxX, desktop.maxX, accuracy: 1)
        XCTAssertEqual(outline.maxY, desktop.maxY, accuracy: 1)
        XCTAssertGreaterThan(panel.frame.maxY, desktop.maxY)
    }

    @MainActor func testHeaderDragMovesTheWindowAndFinishesOnlyOnRelease() async throws {
        _ = NSApplication.shared
        let panel = OverlayPanel(contentRect: CGRect(x: 150, y: 150, width: 1000, height: 563), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.isReleasedWhenClosed = false
        defer { panel.close() }
        let hosting = NSHostingView(rootView: Color.clear)
        hosting.sizingOptions = []
        let surface = OverlaySurface(frame: panel.contentView!.bounds, hosting: hosting)
        panel.contentView = surface
        var finished = 0
        panel.didFinishDragging = { finished += 1 }

        func event(_ type: NSEvent.EventType, at point: CGPoint) throws -> NSEvent {
            try XCTUnwrap(NSEvent.mouseEvent(
                with: type, location: panel.convertPoint(fromScreen: point),
                modifierFlags: [], timestamp: 0, windowNumber: panel.windowNumber,
                context: nil, eventNumber: 0, clickCount: 1, pressure: 1
            ))
        }

        let presentations: [(OverlayOrientation, CGFloat)] = OverlayOrientation.allCases.flatMap { orientation in
            [CGFloat(260), 480, 720, 1000].map { (orientation, $0) }
        }
        for (orientation, width) in presentations {
            surface.orientation = orientation
            panel.setContentSize(CGSize(width: width, height: width * orientation.aspect))
            panel.setFrameOrigin(CGPoint(x: 150, y: 150))
            surface.layoutSubtreeIfNeeded()
            // WindowServer can discard a completely transparent native layer
            // before AppKit hitTest/sendEvent ever receives a real mouse event.
            XCTAssertGreaterThanOrEqual(surface.header.layer?.backgroundColor?.alpha ?? 0, 0.01)
            let scale = width / orientation.canvasWidth
            XCTAssertEqual(surface.header.frame, orientation.header.applying(CGAffineTransform(scaleX: scale, y: scale)))
            let headerPoint = CGPoint(x: orientation.header.midX * scale, y: orientation.header.midY * scale)
            let receiver = surface.hitTest(surface.convert(headerPoint, to: surface.superview))
            XCTAssertTrue(receiver === surface.header)
            XCTAssertTrue(surface.header.acceptsFirstMouse(for: nil))
            let start = panel.frame.origin
            let pointer = panel.convertPoint(toScreen: surface.convert(headerPoint, to: nil))
            let previousFinished = finished
            panel.sendEvent(try event(.leftMouseDown, at: pointer))
            XCTAssertTrue(panel.isDragging)
            XCTAssertEqual(finished, previousFinished)

            // Actual native frame changes, including a second event after the
            // window moved, catch coordinate drift and premature drag completion.
            for delta in [CGPoint(x: 60, y: 24), CGPoint(x: 100, y: 40)] {
                panel.sendEvent(try event(.leftMouseDragged, at: CGPoint(x: pointer.x + delta.x, y: pointer.y + delta.y)))
                XCTAssertEqual(panel.frame.minX, start.x + delta.x, accuracy: 0.001)
                XCTAssertEqual(panel.frame.minY, start.y + delta.y, accuracy: 0.001)
                XCTAssertTrue(panel.isDragging)
                XCTAssertEqual(finished, previousFinished)
            }
            panel.sendEvent(try event(.leftMouseUp, at: CGPoint(x: pointer.x + 100, y: pointer.y + 40)))
            XCTAssertFalse(panel.isDragging)
            XCTAssertEqual(finished, previousFinished + 1)

            // Painted minimize/resize/close and the data buttons must reach SwiftUI.
            let controls = orientation == .mini
                ? [CGPoint(x: 237, y: 67), CGPoint(x: 258, y: 67), CGPoint(x: 278, y: 67), CGPoint(x: 180, y: 220)]
                : orientation == .horizontal
                ? [CGPoint(x: 858, y: 84), CGPoint(x: 900, y: 84), CGPoint(x: 940, y: 84), CGPoint(x: 800, y: 450)]
                : [CGPoint(x: 90, y: 255), CGPoint(x: 190, y: 255), CGPoint(x: 220, y: 255), CGPoint(x: 250, y: 255), CGPoint(x: 170, y: 430)]
            for point in controls {
                let scaled = CGPoint(x: point.x * scale, y: point.y * scale)
                XCTAssertFalse(surface.hitTest(surface.convert(scaled, to: surface.superview)) === surface.header)
                let screenPoint = panel.convertPoint(toScreen: surface.convert(scaled, to: nil))
                panel.sendEvent(try event(.leftMouseDown, at: screenPoint))
                XCTAssertFalse(panel.isDragging)
                panel.sendEvent(try event(.leftMouseUp, at: screenPoint))
            }
        }
        XCTAssertEqual(finished, presentations.count)
    }
}
