import Foundation
import Network
import UIKit

/// Serves one finished package to devices on the same network while its sheet
/// is open. Nothing is uploaded anywhere: receivers download straight from this
/// device. iOS suspends the listener in the background, so the sheet asks the
/// sender to keep the screen on and restarts the listener when it fails.
@MainActor
final class LANShareController: ObservableObject {
    enum Phase: Equatable {
        case starting
        case ready(url: URL)
        case noNetwork
        case failed(String)
    }

    @Published private(set) var phase: Phase = .starting
    @Published private(set) var completedDownloads = 0
    @Published private(set) var activeDownloads = 0
    /// Bytes of the most recent transfer, for a simple progress line.
    @Published private(set) var sentBytes: UInt64 = 0
    let code = LANTransfer.makeCode()
    let fileURL: URL
    let title: String
    let fileSize: UInt64

    private var server: LANFileServer?

    init(fileURL: URL, title: String) {
        self.fileURL = fileURL
        self.title = title
        fileSize = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? NSNumber)?.uint64Value ?? 0
    }

    func start() {
        stop()
        phase = .starting
        let page = LANTransferResponse.page(name: fileURL.lastPathComponent,
            size: ByteCountFormatter.string(fromByteCount: Int64(clamping: fileSize), countStyle: .file),
            download: L10n.tr("下载照片包"), hint: L10n.tr("下载后用 Dropack 打开，或在 mangofund.github.io/dropack 网页查看。"))
        let server = LANFileServer(fileURL: fileURL, fileSize: fileSize, code: code, title: title, page: page) { [weak self] event in
            Task { @MainActor [weak self] in self?.handle(event) }
        }
        self.server = server
        server.start()
        UIApplication.shared.isIdleTimerDisabled = true
    }

    func stop() {
        server?.stop()
        server = nil
        activeDownloads = 0
        UIApplication.shared.isIdleTimerDisabled = false
    }

    /// A suspended listener fails while the app is in the background.
    func sceneDidBecomeActive() {
        switch phase {
        case .failed, .noNetwork: start()
        default: break
        }
    }

    private func handle(_ event: LANFileServer.Event) {
        switch event {
        case let .ready(port):
            guard let host = LANAddress.current(), let url = LANTransfer.pageURL(host: host, port: port, code: code) else {
                phase = .noNetwork
                return
            }
            server?.advertise(host: host, port: port)
            phase = .ready(url: url)
        case let .failed(message):
            server?.stop()
            server = nil
            activeDownloads = 0
            phase = .failed(message)
        case .tooManyAttempts:
            server?.stop()
            server = nil
            activeDownloads = 0
            phase = .failed("错误尝试过多，已停止共享。")
        case .transferStarted:
            activeDownloads += 1
            sentBytes = 0
        case let .progress(bytes):
            sentBytes = bytes
        case let .transferEnded(completed):
            activeDownloads = max(0, activeDownloads - 1)
            if completed { completedDownloads += 1 }
        }
    }
}

enum LANAddress {
    /// The IPv4 address of Wi-Fi (en0), an Ethernet port, or the Personal
    /// Hotspot bridge, in that order.
    static func current() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        var candidates: [(rank: Int, address: String)] = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let interface = pointer.pointee
            guard let address = interface.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  interface.ifa_flags & UInt32(IFF_UP) != 0, interface.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            let name = String(cString: interface.ifa_name)
            let rank: Int
            if name == "en0" { rank = 0 }
            else if name.hasPrefix("en") { rank = 1 }
            else if name.hasPrefix("bridge") { rank = 2 }
            else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count),
                              nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let text = String(cString: host)
            if text.hasPrefix("169.254.") { continue }
            candidates.append((rank, text))
        }
        return candidates.min { $0.rank < $1.rank }?.address
    }
}

/// Queue-confined HTTP/1.1 file server. Each connection carries one request.
final class LANFileServer: @unchecked Sendable {
    enum Event: Sendable {
        case ready(port: UInt16)
        case failed(String)
        case tooManyAttempts
        case transferStarted
        case progress(UInt64)
        case transferEnded(completed: Bool)
    }

    private static let chunkSize = 256 * 1024
    private let queue = DispatchQueue(label: "app.dropack.lan-share")
    private let fileURL: URL
    private let fileSize: UInt64
    private let code: String
    private let title: String
    private let page: String
    private let onEvent: @Sendable (Event) -> Void
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var failedAttempts = 0
    private var stopped = false

    init(fileURL: URL, fileSize: UInt64, code: String, title: String, page: String,
         onEvent: @escaping @Sendable (Event) -> Void) {
        self.fileURL = fileURL
        self.fileSize = fileSize
        self.code = code
        self.title = title
        self.page = page
        self.onEvent = onEvent
    }

    func start() {
        queue.async { [self] in
            do {
                let parameters = NWParameters.tcp
                parameters.includePeerToPeer = false
                let listener = try NWListener(using: parameters, on: .any)
                listener.stateUpdateHandler = { [weak self] state in self?.listenerChanged(state) }
                listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
                self.listener = listener
                listener.start(queue: queue)
            } catch {
                onEvent(.failed(error.localizedDescription))
            }
        }
    }

    func advertise(host: String, port: UInt16) {
        queue.async { [self] in
            guard let listener, !stopped else { return }
            let txt = NWTXTRecord([
                LANTransfer.TXTKey.name: title,
                LANTransfer.TXTKey.size: String(fileSize),
                LANTransfer.TXTKey.host: host,
                LANTransfer.TXTKey.port: String(port),
            ])
            listener.service = NWListener.Service(name: title, type: LANTransfer.serviceType, txtRecord: txt)
        }
    }

    func stop() {
        queue.async { [self] in
            stopped = true
            listener?.cancel()
            listener = nil
            for connection in connections.values { connection.forceCancel() }
            connections.removeAll()
        }
    }

    private func listenerChanged(_ state: NWListener.State) {
        guard !stopped else { return }
        switch state {
        case .ready:
            if let port = listener?.port?.rawValue { onEvent(.ready(port: port)) }
        case let .failed(error):
            onEvent(.failed(error.localizedDescription))
        default:
            break
        }
    }

    private func accept(_ connection: NWConnection) {
        guard !stopped else { connection.cancel(); return }
        let key = ObjectIdentifier(connection)
        connections[key] = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            switch state {
            case .failed, .cancelled:
                self?.connections.removeValue(forKey: key)
                if case .failed = state { connection?.cancel() }
            default: break
            }
        }
        connection.start(queue: queue)
        receiveHead(connection, buffer: Data())
    }

    private func receiveHead(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self, !self.stopped else { connection.cancel(); return }
            var buffer = buffer
            if let data { buffer.append(data) }
            switch LANTransferRequest.parse(buffer) {
            case nil:
                if isComplete || error != nil { connection.cancel() }
                else { self.receiveHead(connection, buffer: buffer) }
            case .failure:
                self.finish(connection, LANTransferResponse.text(status: 400, reason: "Bad Request", body: "Bad Request"))
            case let .success(request):
                self.respond(to: request, on: connection)
            }
        }
    }

    private func respond(to request: LANTransferRequest, on connection: NWConnection) {
        let isHead = request.method == "HEAD"
        guard isHead || request.method == "GET" else {
            finish(connection, LANTransferResponse.text(status: 405, reason: "Method Not Allowed", body: "Method Not Allowed"))
            return
        }
        switch request.route(code: code) {
        case .favicon:
            finish(connection, LANTransferResponse.text(status: 404, reason: "Not Found", body: "", includeBody: !isHead))
        case .notFound:
            failedAttempts += 1
            finish(connection, LANTransferResponse.text(status: 404, reason: "Not Found", body: "Not Found", includeBody: !isHead))
            if failedAttempts >= LANTransfer.maximumFailedAttempts {
                stopped = true
                listener?.cancel()
                onEvent(.tooManyAttempts)
            }
        case .page where !request.path.hasSuffix("/"):
            finish(connection, LANTransferResponse.head(status: 301, reason: "Moved Permanently",
                headers: [("Location", "/\(code)/"), ("Content-Length", "0")]))
        case .page:
            finish(connection, LANTransferResponse.text(status: 200, reason: "OK", body: page,
                                                        type: "text/html; charset=utf-8", includeBody: !isHead))
        case .file:
            let range = LANByteRange.resolve(request.range, size: fileSize)
            let head = LANTransferResponse.fileHead(name: fileURL.lastPathComponent, size: fileSize, range: range)
            let bounds: (UInt64, UInt64)?
            switch range {
            case .whole: bounds = fileSize > 0 ? (0, fileSize - 1) : nil
            case let .partial(lower, upper): bounds = (lower, upper)
            case .unsatisfiable: finish(connection, head); return
            }
            guard !isHead, let bounds else { finish(connection, head); return }
            guard let handle = try? FileHandle(forReadingFrom: fileURL) else {
                finish(connection, LANTransferResponse.text(status: 500, reason: "Internal Server Error", body: "Unavailable"))
                return
            }
            do { try handle.seek(toOffset: bounds.0) } catch {
                try? handle.close()
                finish(connection, LANTransferResponse.text(status: 500, reason: "Internal Server Error", body: "Unavailable"))
                return
            }
            onEvent(.transferStarted)
            connection.send(content: head, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if error != nil { self.endTransfer(connection, handle: handle, completed: false); return }
                self.sendBody(connection, handle: handle, remaining: bounds.1 - bounds.0 + 1, sent: 0)
            })
        }
    }

    private func sendBody(_ connection: NWConnection, handle: FileHandle, remaining: UInt64, sent: UInt64) {
        guard !stopped else { endTransfer(connection, handle: handle, completed: false); return }
        guard remaining > 0 else { endTransfer(connection, handle: handle, completed: true); return }
        let count = Int(min(UInt64(Self.chunkSize), remaining))
        guard let chunk = try? handle.read(upToCount: count), !chunk.isEmpty else {
            endTransfer(connection, handle: handle, completed: false)
            return
        }
        connection.send(content: chunk, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil { self.endTransfer(connection, handle: handle, completed: false); return }
            let total = sent + UInt64(chunk.count)
            self.onEvent(.progress(total))
            self.sendBody(connection, handle: handle, remaining: remaining - UInt64(chunk.count), sent: total)
        })
    }

    private func endTransfer(_ connection: NWConnection, handle: FileHandle, completed: Bool) {
        try? handle.close()
        onEvent(.transferEnded(completed: completed))
        if completed { connection.cancel() } else { connection.forceCancel() }
    }

    private func finish(_ connection: NWConnection, _ response: Data) {
        connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
    }
}
