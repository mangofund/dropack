import Foundation
import Network

/// Finds nearby Dropack senders over Bonjour and downloads one package with the
/// code shown on the sender's screen. The file lands in Application Support and then goes
/// through the same open flow as a file picked in Files.
@MainActor
final class LANReceiveController: ObservableObject {
    struct Sender: Identifiable, Equatable {
        let id: String
        let name: String
        let size: UInt64?
        let host: String
        let port: UInt16
    }

    enum Phase: Equatable {
        case browsing
        case downloading(name: String)
        case failed(String)
    }

    @Published private(set) var senders: [Sender] = []
    @Published private(set) var phase: Phase = .browsing
    @Published private(set) var fraction: Double = 0
    @Published private(set) var permissionProblem = false

    private var browser: NWBrowser?
    private var task: URLSessionDownloadTask?
    private var progressTimer: Timer?

    func startBrowsing() {
        browser?.cancel()
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: LANTransfer.serviceType, domain: nil), using: .tcp)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let senders = results.compactMap(Self.sender(from:)).sorted { $0.name < $1.name }
            Task { @MainActor [weak self] in self?.senders = senders }
        }
        browser.stateUpdateHandler = { [weak self] state in
            let denied: Bool
            // kDNSServiceErr_PolicyDenied: Local Network access was turned off.
            if case let .waiting(error) = state, case let .dns(code) = error, code == -65570 { denied = true }
            else { denied = false }
            Task { @MainActor [weak self] in self?.permissionProblem = denied }
        }
        self.browser = browser
        browser.start(queue: .main)
    }

    func stop() {
        browser?.cancel()
        browser = nil
        cancelDownload()
    }

    func cancelDownload() {
        task?.cancel()
        task = nil
        progressTimer?.invalidate()
        progressTimer = nil
        if case .downloading = phase { phase = .browsing }
    }

    func clearFailure() {
        if case .failed = phase { phase = .browsing }
    }

    nonisolated private static func sender(from result: NWBrowser.Result) -> Sender? {
        guard case let .bonjour(record) = result.metadata,
              let host = record[LANTransfer.TXTKey.host], !host.isEmpty,
              let portText = record[LANTransfer.TXTKey.port], let port = UInt16(portText) else { return nil }
        var name = record[LANTransfer.TXTKey.name] ?? ""
        if name.isEmpty, case let .service(serviceName, _, _, _) = result.endpoint { name = serviceName }
        return Sender(id: "\(host):\(port)", name: name, size: record[LANTransfer.TXTKey.size].flatMap(UInt64.init),
                      host: host, port: port)
    }

    /// Returns the downloaded package, or nil when cancelled or failed.
    func download(from sender: Sender, code: String) async -> URL? {
        guard task == nil else { return nil }
        guard LANTransfer.isValidCode(code) else {
            phase = .failed("请输入 6 位数字接收码。")
            return nil
        }
        guard let url = LANTransfer.fileURL(host: sender.host, port: sender.port, code: code) else { return nil }
        phase = .downloading(name: sender.name)
        fraction = 0
        let folder = Self.downloadRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let fallbackName = sender.name
        let result: Result<URL, Error> = await withCheckedContinuation { continuation in
            var request = URLRequest(url: url)
            request.timeoutInterval = 30
            let task = URLSession.shared.downloadTask(with: request) { location, response, error in
                // The temporary file disappears when this handler returns.
                continuation.resume(returning: Result {
                    if let error { throw error }
                    guard let location, let http = response as? HTTPURLResponse else { throw LANReceiveError.unreachable }
                    if http.statusCode == 404 { throw LANReceiveError.wrongCode }
                    guard http.statusCode == 200 else { throw LANReceiveError.unreachable }
                    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                    let destination = folder.appendingPathComponent(Self.fileName(suggested: response?.suggestedFilename,
                                                                                  fallback: fallbackName))
                    try FileManager.default.moveItem(at: location, to: destination)
                    return destination
                })
            }
            self.task = task
            progressTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self, weak task] _ in
                MainActor.assumeIsolated {
                    if let progress = task?.progress, progress.totalUnitCount > 0 { self?.fraction = progress.fractionCompleted }
                }
            }
            task.resume()
        }
        let cancelled = task == nil
        task = nil
        progressTimer?.invalidate()
        progressTimer = nil
        switch result {
        case let .success(file):
            if cancelled { try? FileManager.default.removeItem(at: folder); return nil }
            phase = .browsing
            return file
        case let .failure(error):
            try? FileManager.default.removeItem(at: folder)
            if cancelled || (error as? URLError)?.code == .cancelled { return nil }
            phase = .failed((error as? LANReceiveError)?.errorDescription ?? "无法连接发送方，请确认两台设备在同一个 Wi-Fi。")
            return nil
        }
    }

    /// Kept like an AirDrop inbox copy: an unfinished import may need to read
    /// its source again when it resumes.
    nonisolated static var downloadRoot: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("LANReceived", isDirectory: true)
    }

    nonisolated static func fileName(suggested: String?, fallback: String) -> String {
        var name = (suggested ?? "").replacingOccurrences(of: "/", with: "_")
        if name.isEmpty || name.hasPrefix(".") { name = fallback.replacingOccurrences(of: "/", with: "_") }
        if name.isEmpty { name = "Dropack" }
        let lower = name.lowercased()
        if !lower.hasSuffix("." + PackageFileFormat.dropack.fileExtension) && !lower.hasSuffix(".zip") {
            name += "." + PackageFileFormat.dropack.fileExtension
        }
        return name
    }
}

enum LANReceiveError: Error, LocalizedError {
    case wrongCode, unreachable
    var errorDescription: String? {
        switch self {
        case .wrongCode: return "接收码不正确，请看发送方屏幕上的 6 位数字。"
        case .unreachable: return "无法连接发送方，请确认两台设备在同一个 Wi-Fi。"
        }
    }
}
