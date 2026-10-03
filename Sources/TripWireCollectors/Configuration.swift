import Foundation
import SystemConfiguration
import TripWireCore

public struct ConfigurationCollector: Collector {
    public let descriptor = SensorDescriptor("configuration", "Security posture / DNS / proxy", source: "SystemConfiguration SCDynamicStore, csrutil(1), fdesetup(8), spctl(8), socketfilterfw(8), launchctl(1)", monitors: "Read-only posture summaries and allowlisted network configuration metadata", limitations: ["Secure Boot policy, complete VPN state, MDM profile contents and actual service reachability are NOT OBSERVABLE here.", "launchctl disabled overrides do not prove a service is running or externally reachable.", "Global DNS/proxy settings are not all per-service or application-specific settings.", "No security or network setting is modified; no elevation is requested."])
    public init() {}
    public func collect() async -> CollectorSnapshot {
        var observations: [Observation] = [], failures = 0
        let sources: [(String, String, [String], String)] = [
            ("sip", "/usr/bin/csrutil", ["status"], "System Integrity Protection status:"),
            ("filevault", "/usr/bin/fdesetup", ["status"], "FileVault"),
            ("gatekeeper", "/usr/sbin/spctl", ["--status"], "assessments"),
            ("firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], "Firewall")
        ]
        for (key, path, args, expected) in sources {
            let result = ReadCommand.run(path, args)
            let text = result.text.trimmingCharacters(in: .whitespacesAndNewlines)
            if result.successful && text.contains(expected) && text.count < 2048 && result.error.isEmpty {
                observations.append(Observation(key: key, eventClass: .configuration, component: key.uppercased(), attributes: ["reportedState": text], limitations: descriptor.limitations))
            } else { failures += 1 }
        }
        if let store = SCDynamicStoreCreate(nil, "TripWire read-only inventory" as CFString, nil, nil) {
            for (name, key, allowed) in [
                ("dns", "State:/Network/Global/DNS", ["ServerAddresses", "SearchDomains", "DomainName"]),
                ("proxy", "State:/Network/Global/Proxies", ["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort", "SOCKSEnable", "SOCKSProxy", "SOCKSPort", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"])
            ] {
                if let values = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] {
                    var attrs: [String: String] = [:]
                    for field in allowed {
                        if let array = values[field] as? [String] { attrs[field] = array.sorted().joined(separator: ", ") }
                        else if let value = values[field] { attrs[field] = String(describing: value) }
                    }
                    attrs["scope"] = "Global dynamic store; missing keys UNSPECIFIED"
                    observations.append(Observation(key: name, eventClass: .configuration, component: name.uppercased(), attributes: attrs, limitations: descriptor.limitations))
                } else { failures += 1 }
            }
        } else { failures += 2 }
        let launch = ReadCommand.run("/bin/launchctl", ["print-disabled", "system"])
        if launch.successful {
            for label in ["com.openssh.sshd", "com.apple.screensharing", "com.apple.RemoteDesktop.PrivilegeProxy"] {
                let line = launch.text.split(separator: "\n").first { $0.contains("\"\(label)\"") }
                let value = line?.contains("=> true") == true ? "DISABLED override" : line?.contains("=> false") == true ? "ENABLED override" : "UNKNOWN (no explicit override)"
                observations.append(Observation(key: label, eventClass: .configuration, component: label, attributes: ["launchdOverride": value, "runningState": "UNKNOWN", "externalReachability": "UNKNOWN"], limitations: descriptor.limitations, confidence: .moderate))
            }
        } else { failures += 1 }
        return CollectorSnapshot(descriptor: descriptor, observations: observations, complete: failures == 0, state: .degraded, detail: "\(observations.count) configuration records; \(failures) unavailable sources. Missing values are UNKNOWN.")
    }
}
