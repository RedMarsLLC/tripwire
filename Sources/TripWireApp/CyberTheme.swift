import SwiftUI

enum CyberTheme {
    static let cyan = Color(red: 0.05, green: 0.91, blue: 1)
    static let pink = Color(red: 1, green: 0.14, blue: 0.69)
    static let muted = Color(red: 0.52, green: 0.69, blue: 0.75)
    static let line = LinearGradient(colors: [cyan.opacity(0.55), cyan.opacity(0.10), pink.opacity(0.55)], startPoint: .topLeading, endPoint: .bottomTrailing)
}
let ink = Color(red: 0.012, green: 0.028, blue: 0.045)
let panel = Color(red: 0.023, green: 0.055, blue: 0.078)
let accent = CyberTheme.cyan

struct CyberCut: Shape {
    var cut: CGFloat = 10
    func path(in r: CGRect) -> Path {
        let c = min(cut, min(r.width, r.height) / 3)
        return Path { p in
            p.move(to: CGPoint(x: r.minX + c, y: r.minY)); p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
            p.addLine(to: CGPoint(x: r.maxX, y: r.maxY - c)); p.addLine(to: CGPoint(x: r.maxX - c, y: r.maxY))
            p.addLine(to: CGPoint(x: r.minX, y: r.maxY)); p.addLine(to: CGPoint(x: r.minX, y: r.minY + c)); p.closeSubpath()
        }
    }
}
struct CyberBackground: View {
    var body: some View {
        ZStack {
            ink
            LinearGradient(colors: [accent.opacity(0.065), .clear, CyberTheme.pink.opacity(0.035)], startPoint: .topLeading, endPoint: .bottomTrailing)
            Canvas { context, size in
                var grid = Path()
                for x in stride(from: CGFloat(0), through: size.width, by: 32) { grid.move(to: CGPoint(x: x, y: 0)); grid.addLine(to: CGPoint(x: x, y: size.height)) }
                for y in stride(from: CGFloat(0), through: size.height, by: 32) { grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: size.width, y: y)) }
                context.stroke(grid, with: .color(accent.opacity(0.035)), lineWidth: 0.5)
            }
        }.allowsHitTesting(false).accessibilityHidden(true)
    }
}
private struct CyberPanel: ViewModifier {
    func body(content: Content) -> some View {
        content.background(panel.opacity(0.95), in: CyberCut())
            .overlay(CyberCut().stroke(CyberTheme.line, lineWidth: 0.75).allowsHitTesting(false))
    }
}
extension View { func cyberPanel() -> some View { modifier(CyberPanel()) } }

struct CyberButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: 12, weight: .semibold, design: .monospaced))
            .foregroundStyle(enabled ? accent : CyberTheme.muted).padding(.horizontal, 12).padding(.vertical, 8)
            .background((configuration.isPressed ? accent.opacity(0.22) : panel), in: CyberCut(cut: 6))
            .overlay(CyberCut(cut: 6).stroke(accent.opacity(enabled ? 0.5 : 0.15), lineWidth: 0.75))
            .opacity(enabled ? 1 : 0.55)
    }
}

struct CyberWordmark: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("TripWire").font(.system(size: 32, weight: .black, design: .rounded)).italic()
                .foregroundStyle(LinearGradient(colors: [accent, .white, CyberTheme.pink], startPoint: .topLeading, endPoint: .bottomTrailing))
                .shadow(color: accent.opacity(0.3), radius: 8)
            Text("YOUR CYBER WATCHDOG").font(.system(size: 8, weight: .bold, design: .monospaced)).tracking(2).foregroundStyle(accent)
        }.accessibilityElement(children: .combine)
    }
}
