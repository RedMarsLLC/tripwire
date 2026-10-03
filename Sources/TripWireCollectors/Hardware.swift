import Foundation
import IOKit
import TripWireCore

public struct HardwareCollector: Collector {
    public let descriptor = SensorDescriptor("hardware", "USB and storage devices", source: "IOKit IOServiceGetMatchingServices + IORegistryEntryCreateCFProperty", monitors: "IOUSBHostDevice and whole IOMedia registry entries", limitations: ["Registry IDs are not cryptographic device identities and may change after reboot/reconnection.", "Serial numbers and storage contents are not collected.", "Bluetooth connections and all peripheral classes are not covered.", "Polling may miss brief attachments."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        var observations: [Observation] = [], failed = false
        for className in ["IOUSBHostDevice", "IOMedia"] {
            var iterator: io_iterator_t = 0
            guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(className), &iterator) == KERN_SUCCESS else { failed = true; continue }
            defer { IOObjectRelease(iterator) }
            while case let service = IOIteratorNext(iterator), service != 0 {
                defer { IOObjectRelease(service) }
                func property(_ key: String) -> Any? { IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() }
                if className == "IOMedia", property("Whole") as? Bool != true { continue }
                var registryID: UInt64 = 0
                guard IORegistryEntryGetRegistryEntryID(service, &registryID) == KERN_SUCCESS else { failed = true; continue }
                var attrs = ["deviceClass": className, "registryID": String(registryID)]
                for key in ["USB Vendor Name", "USB Product Name", "idVendor", "idProduct", "bDeviceClass", "BSD Name", "Removable", "Ejectable"] {
                    if let value = property(key) { attrs[key] = String(describing: value) }
                }
                observations.append(Observation(key: "\(className):\(registryID)", eventClass: .hardware, component: attrs["USB Product Name"] ?? attrs["BSD Name"] ?? className, attributes: attrs, limitations: descriptor.limitations))
            }
        }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: !failed, state: failed ? .error : .active, visibility: .limited, detail: failed ? "IOKit inventory partially failed; no removals inferred" : "\(observations.count) USB/whole-storage records")
    }
}
