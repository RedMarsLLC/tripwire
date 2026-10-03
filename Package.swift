// swift-tools-version: 5.9
import PackageDescription

// Use the Apple SDK's SQLite on macOS; Homebrew may target a newer OS than our app.
#if os(macOS)
let sqlitePkgConfig: String? = nil
#else
let sqlitePkgConfig: String? = "sqlite3"
#endif
var products: [Product] = [
    .executable(name: "tripwire", targets: ["TripWireCLI"]),
    .library(name: "TripWireCore", targets: ["TripWireCore"])
]
var targets: [Target] = [
    .systemLibrary(name: "CSQLite", pkgConfig: sqlitePkgConfig, providers: [.apt(["libsqlite3-dev"]), .brew(["sqlite3"])]),
    .target(name: "CTripWirePlatform", cSettings: [.define("_WIN32_WINNT", to: "0x0A00", .when(platforms: [.windows]))], linkerSettings: [
        .linkedLibrary("crypto", .when(platforms: [.linux])),
        .linkedLibrary("bcrypt", .when(platforms: [.windows])),
        .linkedLibrary("advapi32", .when(platforms: [.windows])),
        .linkedLibrary("iphlpapi", .when(platforms: [.windows])),
        .linkedLibrary("psapi", .when(platforms: [.windows]))
    ]),
    .target(name: "TripWireCore", dependencies: ["CSQLite", "CTripWirePlatform"]),
    .target(name: "TripWireTerminal", dependencies: ["TripWireCore", "CTripWirePlatform"]),
    .executableTarget(name: "TripWireCLI", dependencies: ["TripWireCore", "TripWireCollectors", "TripWireTerminal", "CTripWirePlatform"]),
    .testTarget(name: "TripWirePortableTests", dependencies: ["TripWireCore", "TripWireCollectors", "TripWireTerminal"])
]
#if os(macOS)
products.append(.executable(name: "TripWireApp", targets: ["TripWireApp"]))
targets += [
    .target(name: "TripWireCollectors", dependencies: ["TripWireCore"], exclude: ["Linux", "Windows", "PortableRegistry.swift", "PortableMetrics.swift"]),
    .executableTarget(name: "TripWireApp", dependencies: ["TripWireCore", "TripWireCollectors"], resources: [.copy("Resources/OverlayFrame.png"), .copy("Resources/OverlayFrameVertical.png"), .copy("Resources/OverlayFrameMini.png"), .copy("Resources/AppIcon.icns")]),
    .testTarget(name: "TripWireTests", dependencies: ["TripWireCore", "TripWireCollectors", "TripWireTerminal"], resources: [.copy("Fixtures")]),
    .testTarget(name: "TripWireAppTests", dependencies: ["TripWireApp"])
]
#else
#if os(Windows)
let otherPlatform = "Linux"
let collectorSources = ["Windows", "PortableRegistry.swift", "PortableMetrics.swift", "Monitor.swift", "FileWatchSession.swift", "UnavailableCollector.swift"]
#else
let otherPlatform = "Windows"
let collectorSources = ["Linux", "PortableRegistry.swift", "PortableMetrics.swift", "Monitor.swift", "FileWatchSession.swift", "UnavailableCollector.swift"]
#endif
targets.append(.target(name: "TripWireCollectors", dependencies: ["TripWireCore", "CTripWirePlatform"], exclude: [otherPlatform, "Support.swift", "BoundedSignatureLookup.swift", "AIFileAccess.swift", "Persistence.swift", "Extensions.swift", "Processes.swift", "HostResourceSampler.swift", "Hardware.swift", "SelfIntegrity.swift", "Applications.swift", "Registry.swift", "AgentIntegrationProbe.swift", "Configuration.swift", "Network.swift", "AIAppResourceSampler.swift"], sources: collectorSources))
#endif
let package = Package(name: "TripWire", platforms: [.macOS(.v14)], products: products, targets: targets)
