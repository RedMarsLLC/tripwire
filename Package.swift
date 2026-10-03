// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TripWire", platforms: [.macOS(.v14)],
    products: [
        .executable(name: "tripwire", targets: ["TripWireCLI"]),
        .executable(name: "TripWireApp", targets: ["TripWireApp"]),
        .library(name: "TripWireCore", targets: ["TripWireCore"])
    ],
    targets: [
        .systemLibrary(name: "CSQLite", pkgConfig: "sqlite3"),
        .target(name: "TripWireCore", dependencies: ["CSQLite"]),
        .target(name: "TripWireCollectors", dependencies: ["TripWireCore"]),
        .target(name: "TripWireTerminal", dependencies: ["TripWireCore"]),
        .executableTarget(name: "TripWireCLI", dependencies: ["TripWireCore", "TripWireCollectors", "TripWireTerminal"]),
        .executableTarget(name: "TripWireApp", dependencies: ["TripWireCore", "TripWireCollectors"], resources: [.copy("Resources/OverlayFrame.png"), .copy("Resources/OverlayFrameVertical.png"), .copy("Resources/OverlayFrameMini.png"), .copy("Resources/AppIcon.icns")]),
        .testTarget(name: "TripWireTests", dependencies: ["TripWireCore", "TripWireCollectors", "TripWireTerminal"], resources: [.copy("Fixtures")]),
        .testTarget(name: "TripWireAppTests", dependencies: ["TripWireApp"])
    ]
)
