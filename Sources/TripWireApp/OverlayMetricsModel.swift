import AppKit
import Combine
import TripWireCore
import TripWireCollectors

@MainActor final class OverlayMetricsModel: ObservableObject {
    @Published private(set) var resources = ResourceMetrics()
    @Published private(set) var appResources = AppResourceMetrics()
    @Published private(set) var hooks = AgentActivityView()
    @Published private(set) var hookHistory = AgentActivityHistory()
    @Published private(set) var isSampling = false
    @Published private(set) var isVisible = false
    private let worker = DispatchQueue(label: "TripWire.overlay.agents", qos: .utility)
    private let appWorker = DispatchQueue(label: "TripWire.overlay.app-resources", qos: .utility)
    private var appWorkerBusy = false
    private var workerBusy = false
    private var epoch = UUID()
    private var storeURL = EventStore.defaultURL
    private var timer: Timer?
    private var pressureSource: DispatchSourceMemoryPressure?
    private var pressureGeneration = UUID()
    private var enabled = false
    private var asleep = false
    private var samplingActivity: NSObjectProtocol?
    private let sample: () -> HostResourceCounters
    private let now: () -> Date
    private let applications: @MainActor () -> [AIApplication]
    private let sampleApps: ([AIApplication]) -> AppResourceSample

    init(sample: @escaping () -> HostResourceCounters = HostResourceSampler.sample, now: @escaping () -> Date = Date.init,
         applications: @escaping @MainActor () -> [AIApplication] = { AIAppResourceSampler.applications() },
         sampleApps: @escaping ([AIApplication]) -> AppResourceSample = AIAppResourceSampler.sample) {
        self.sample = sample; self.now = now
        self.applications = applications; self.sampleApps = sampleApps
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(willSleep), name: NSWorkspace.willSleepNotification, object: nil)
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(shutdown), name: NSApplication.willTerminateNotification, object: nil)
    }
    deinit {
        timer?.invalidate(); pressureSource?.cancel()
        if let samplingActivity { ProcessInfo.processInfo.endActivity(samplingActivity) }
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        NotificationCenter.default.removeObserver(self)
    }
    func configure(storeURL: URL) {
        guard self.storeURL != storeURL else { return }
        self.storeURL = storeURL; epoch = UUID()
        hooks = AgentActivityView(); hookHistory = AgentActivityHistory()
    }
    func setVisible(_ value: Bool) {
        isVisible = value
        // Opening opts into resource sampling for this app session. The panel
        // controls presentation only; hiding it must not create missing data.
        if value {
            enabled = true
            if !asleep { start() }
        }
    }
    @objc func shutdown() {
        enabled = false; isVisible = false
        stop(reason: "TripWire resource sampling stopped")
    }
    private func start() {
        guard timer == nil else { return }
        isSampling = true
        // Keep the user-requested one-second sampler out of App Nap while its
        // window is hidden. This activity explicitly permits normal Mac sleep.
        samplingActivity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
            reason: "Maintain TripWire resource history while the overlay is hidden")
        resetPressureSource()
        tick()
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.tick() }
        }
        timer.tolerance = 0.15
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }
    private func tick() {
        guard enabled, !asleep else { return }
        let hadSample = resources.lastSample != nil
        let continuous = resources.ingest(sample())
        if hadSample && !continuous { resetPressureSource() }
        sampleApplications()
        sampleAgents()
    }
    private func sampleApplications() {
        guard !appWorkerBusy else { return }
        appWorkerBusy = true
        let generation = epoch, apps = applications(), sample = sampleApps
        appWorker.async { [weak self] in
            let reading = sample(apps)
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.appWorkerBusy = false
                guard self.epoch == generation, self.isSampling else { return }
                self.appResources.ingest(reading)
            }
        }
    }
    private func sampleAgents() {
        guard !workerBusy else { return }
        workerBusy = true
        let generation = epoch, url = storeURL, date = now()
        worker.async { [weak self] in
            let hookView: AgentActivityView
            do {
                let reader = try EventStore(url: url, access: .readOnly)
                hookView = try reader.readSnapshot { try reader.agentActivity(now: date) }
            } catch { hookView = AgentActivityView(error: "Hook evidence unavailable") }
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.workerBusy = false
                guard self.epoch == generation, self.isSampling else { return }
                self.hooks = hookView
                self.hookHistory.ingest(hookView, at: date)
            }
        }
    }
    private func stop(reason: String) {
        isSampling = false; epoch = UUID()
        hookHistory.interrupt(at: now())
        appResources.interrupt(at: now(), reason: reason)
        timer?.invalidate(); timer = nil
        if let samplingActivity { ProcessInfo.processInfo.endActivity(samplingActivity); self.samplingActivity = nil }
        pressureGeneration = UUID(); pressureSource?.cancel(); pressureSource = nil
        resources.interrupt(at: now(), reason: reason)
    }
    private func resetPressureSource() {
        pressureSource?.cancel()
        let generation = UUID(); pressureGeneration = generation
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.normal, .warning, .critical], queue: .main)
        source.setEventHandler { [weak self, weak source] in
            guard let source else { return }
            let flags = source.data
            let value: MemoryPressure = flags.contains(.critical) ? .critical : flags.contains(.warning) ? .warning : flags.contains(.normal) ? .normal : .unknown
            Task { @MainActor [weak self] in
                guard let self, self.isSampling, !self.asleep, self.pressureGeneration == generation else { return }
                self.resources.updatePressure(value, at: self.now())
            }
        }
        pressureSource = source
        source.activate()
    }
    @objc private func willSleep() { asleep = true; if enabled { stop(reason: "Sleep; resource coverage interrupted") } }
    @objc private func didWake() { asleep = false; if enabled { start() } }
}
