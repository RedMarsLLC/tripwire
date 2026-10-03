import Foundation
import TripWireCore

public struct UnavailableCollector: Collector {
    public let descriptor: SensorDescriptor
    public let reason: String
    public let state: SensorState
    public init(_ descriptor: SensorDescriptor, reason: String, state: SensorState = .unsupported) { self.descriptor = descriptor; self.reason = reason; self.state = state }
    public func collect() async -> CollectorSnapshot { CollectorSnapshot(descriptor: descriptor, state: state, visibility: .unavailable, detail: reason) }
}
