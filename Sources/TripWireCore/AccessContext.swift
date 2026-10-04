import Foundation

/// Explains retained metadata without inferring physical input or reading contents.
public enum AccessContext {
    public static func isMonitoringAccount(_ row: Observation) -> Bool {
        if let uid = row.process?.uid, let collector = row.attributes["collectorUID"].flatMap(UInt32.init) { return uid == collector }
        if let sid = row.process?.accountID, !sid.isEmpty, let collector = row.attributes["collectorAccountSID"] { return sid == collector }
        return false
    }
    public static func text(_ event: EvidenceEvent) -> String? {
        let row = event.observation
        guard row.eventClass == .file || row.eventClass == .process else { return nil }
        let a = row.attributes, p = row.process
        let executable = p?.executablePath ?? a["executable"] ?? "Unknown"
        let operation = a["operation"] ?? (row.eventClass == .process ? "Running process sampled; launch event not observed" : "Open descriptor sampled; actual read/write unknown")
        let account = p?.uid.map { "UID \($0)" } ?? p?.accountID ?? "Unknown"
        let names = [executable, a["parentExecutable"], a["responsibleExecutable"]].compactMap { $0 }.map { URL(fileURLWithPath: $0).lastPathComponent.lowercased() }
        let commandTools: Set<String> = ["sh", "bash", "zsh", "fish", "dash", "cat", "head", "tail", "cp", "mv", "rm", "touch", "python", "python3", "node", "pwsh", "pwsh.exe", "powershell.exe", "cmd.exe", "iterm2", "terminal", "windowsterminal.exe"]
        let method = names.contains(where: commandTools.contains) ? "Command-line tool or terminal in the recorded process context (inferred from executable name; not proof of who invoked it)." : "An application or other process performed the operation; initiation method unknown."
        let parent = a["parentExecutable"] ?? "Executable unknown"
        let responsible = a["responsibleExecutable"] ?? "Executable unknown"
        return """
        Operation: \(operation)
        Capability: \(a["openMode"] ?? "Not recorded / not applicable")
        Process: \(executable) · PID \(p?.pid.map(String.init) ?? "Unknown")
        Account: \(account)\(isMonitoringAccount(row) ? " · monitoring account" : "")
        Parent: \(parent) · PID \(p?.parentPID.map(String.init) ?? "Unknown")
        OS-reported responsible process: \(responsible) · PID \(a["responsiblePID"] ?? "Unknown")
        Access method: \(method)
        Mouse vs keyboard vs automation: Unknown. Input events are not collected; process ancestry cannot distinguish them.
        AI association: \(a["associatedApp"] ?? "Unknown")\(a["associationBasis"].map { " · " + $0 } ?? "")
        Source: \(event.sourceCollector) · \(TimeText.iso(event.timestamp))
        Contents and input were not recorded. Association does not establish user authorization, an AI instruction or intent.
        """
    }
}
