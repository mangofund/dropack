import Foundation

/// Wire rules for sending a finished package to another device on the same
/// network. The sender serves one file over plain HTTP/1.1 at
/// `http://<address>:<port>/<code>/file`, with a landing page at `/<code>/`.
/// Dropack receivers find senders through Bonjour (`_dropack._tcp`); browsers
/// use the address shown on screen or in the QR code. The six-digit code keeps
/// other people on the network from guessing the file, and the server stops
/// after too many wrong attempts.
public enum LANTransfer {
    public static let serviceType = "_dropack._tcp"
    public static let codeLength = 6
    public static let maximumFailedAttempts = 30
    public static let maximumRequestHeaderBytes = 16 * 1024

    /// Bonjour TXT keys. The code is never advertised.
    public enum TXTKey {
        public static let name = "n"
        public static let size = "s"
        public static let host = "h"
        public static let port = "p"
    }

    public static func makeCode() -> String {
        (0..<codeLength).map { _ in String(Int.random(in: 0...9)) }.joined()
    }

    public static func isValidCode(_ code: String) -> Bool {
        code.count == codeLength && code.allSatisfy { $0.isASCII && $0.isNumber }
    }

    public static func pageURL(host: String, port: UInt16, code: String) -> URL? {
        URL(string: "http://\(formattedHost(host)):\(port)/\(code)/")
    }

    public static func fileURL(host: String, port: UInt16, code: String) -> URL? {
        URL(string: "http://\(formattedHost(host)):\(port)/\(code)/file")
    }

    private static func formattedHost(_ host: String) -> String {
        host.contains(":") ? "[\(host)]" : host
    }
}

public struct LANTransferRequest: Equatable, Sendable {
    public var method: String
    public var path: String
    public var range: String?

    /// Parses a request head ending in CRLFCRLF. Returns nil while incomplete.
    public static func parse(_ data: Data) -> Result<LANTransferRequest, LANTransferRequestError>? {
        guard let end = data.range(of: Data("\r\n\r\n".utf8)) else {
            return data.count > LANTransfer.maximumRequestHeaderBytes ? .failure(.malformed) : nil
        }
        guard let head = String(data: data[data.startIndex..<end.lowerBound], encoding: .utf8) else {
            return .failure(.malformed)
        }
        let lines = head.components(separatedBy: "\r\n")
        let parts = lines[0].split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/1.") else { return .failure(.malformed) }
        var range: String?
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            if line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "range" {
                range = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        var path = String(parts[1])
        if let query = path.firstIndex(where: { $0 == "?" || $0 == "#" }) { path = String(path[..<query]) }
        return .success(LANTransferRequest(method: String(parts[0]), path: path, range: range))
    }

    public enum Route: Equatable, Sendable {
        case page, file, favicon, notFound
    }

    public func route(code: String) -> Route {
        if path == "/favicon.ico" { return .favicon }
        if path == "/\(code)" || path == "/\(code)/" { return .page }
        if path == "/\(code)/file" { return .file }
        return .notFound
    }
}

public enum LANTransferRequestError: Error, Equatable, Sendable {
    case malformed
}

public enum LANByteRange: Equatable, Sendable {
    case whole
    case partial(lower: UInt64, upper: UInt64)
    case unsatisfiable

    /// Supports a single `bytes=a-b`, `bytes=a-` or `bytes=-n` range. Anything
    /// else (multiple ranges, other units) is answered with the whole file.
    public static func resolve(_ header: String?, size: UInt64) -> LANByteRange {
        guard let header, header.lowercased().hasPrefix("bytes=") else { return .whole }
        let spec = header.dropFirst("bytes=".count).trimmingCharacters(in: .whitespaces)
        guard !spec.contains(","), let dash = spec.firstIndex(of: "-") else { return .whole }
        let first = spec[..<dash], last = spec[spec.index(after: dash)...]
        if first.isEmpty {
            guard let suffix = UInt64(last), suffix > 0 else { return .unsatisfiable }
            guard size > 0 else { return .unsatisfiable }
            return .partial(lower: size - min(suffix, size), upper: size - 1)
        }
        guard let lower = UInt64(first) else { return .whole }
        guard lower < size else { return .unsatisfiable }
        if last.isEmpty { return .partial(lower: lower, upper: size - 1) }
        guard let upper = UInt64(last), upper >= lower else { return .whole }
        return .partial(lower: lower, upper: min(upper, size - 1))
    }
}

public enum LANTransferResponse {
    public static func head(status: Int, reason: String, headers: [(String, String)]) -> Data {
        var text = "HTTP/1.1 \(status) \(reason)\r\n"
        for (name, value) in headers + [("Connection", "close"), ("Cache-Control", "no-store")] {
            text += "\(name): \(value)\r\n"
        }
        return Data((text + "\r\n").utf8)
    }

    public static func text(status: Int, reason: String, body: String, type: String = "text/plain; charset=utf-8",
                            includeBody: Bool = true) -> Data {
        let bytes = Data(body.utf8)
        var data = head(status: status, reason: reason, headers: [("Content-Type", type),
                                                                  ("Content-Length", String(bytes.count))])
        if includeBody { data.append(bytes) }
        return data
    }

    public static func fileHead(name: String, size: UInt64, range: LANByteRange) -> Data {
        var headers: [(String, String)] = [
            ("Content-Type", "application/octet-stream"),
            ("Content-Disposition", contentDisposition(name)),
            ("Accept-Ranges", "bytes"),
        ]
        switch range {
        case .whole:
            headers.append(("Content-Length", String(size)))
            return head(status: 200, reason: "OK", headers: headers)
        case let .partial(lower, upper):
            headers.append(("Content-Length", String(upper - lower + 1)))
            headers.append(("Content-Range", "bytes \(lower)-\(upper)/\(size)"))
            return head(status: 206, reason: "Partial Content", headers: headers)
        case .unsatisfiable:
            return head(status: 416, reason: "Range Not Satisfiable",
                        headers: [("Content-Range", "bytes */\(size)"), ("Content-Length", "0")])
        }
    }

    /// RFC 6266 with an ASCII fallback, so Chinese album names survive.
    static func contentDisposition(_ name: String) -> String {
        let ascii = String(name.unicodeScalars.map { scalar in
            scalar.isASCII && scalar.value >= 0x20 && scalar != "\"" && scalar != "\\" ? Character(scalar) : "_"
        })
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        let encoded = name.addingPercentEncoding(withAllowedCharacters: allowed) ?? ascii
        return "attachment; filename=\"\(ascii)\"; filename*=UTF-8''\(encoded)"
    }

    /// `download` and `hint` arrive already localized from the app.
    public static func page(name: String, size: String, download: String, hint: String) -> String {
        let title = escape(name)
        return """
        <!doctype html><html><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>\(title) · Dropack</title>
        <style>
        body{margin:0;font:16px/1.5 -apple-system,system-ui,sans-serif;background:#f6f5f2;color:#1d1d1f}
        main{max-width:440px;margin:0 auto;padding:48px 20px}
        .card{background:#fff;border-radius:20px;padding:24px}
        h1{font-size:20px;margin:0 0 4px;word-break:break-word}
        p{margin:0 0 16px;color:#6e6e73}
        a.button{display:block;text-align:center;background:#1d1d1f;color:#fff;text-decoration:none;
        padding:14px;border-radius:14px;font-weight:600}
        small{display:block;margin-top:16px;color:#6e6e73}
        @media(prefers-color-scheme:dark){body{background:#000;color:#f5f5f7}.card{background:#1c1c1e}
        a.button{background:#f5f5f7;color:#000}}
        </style></head><body><main><div class="card">
        <h1>\(title)</h1><p>\(escape(size))</p>
        <a class="button" href="file" download>\(escape(download))</a>
        <small>\(escape(hint))</small>
        </div></main></body></html>
        """
    }

    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }
}
