import XCTest
@testable import RelayCore

final class LANTransferTests: XCTestCase {
    func testCodesAreSixDigits() {
        for _ in 0..<50 {
            let code = LANTransfer.makeCode()
            XCTAssertTrue(LANTransfer.isValidCode(code), code)
        }
        XCTAssertFalse(LANTransfer.isValidCode("12345"))
        XCTAssertFalse(LANTransfer.isValidCode("12345a"))
        XCTAssertFalse(LANTransfer.isValidCode("١٢٣٤٥٦"))
    }

    func testURLs() {
        XCTAssertEqual(LANTransfer.pageURL(host: "192.168.1.5", port: 5123, code: "042817")?.absoluteString,
                       "http://192.168.1.5:5123/042817/")
        XCTAssertEqual(LANTransfer.fileURL(host: "fe80::1", port: 80, code: "000001")?.absoluteString,
                       "http://[fe80::1]:80/000001/file")
    }

    func testParsesRequestHead() throws {
        XCTAssertNil(LANTransferRequest.parse(Data("GET /123456/file HTTP/1.1\r\nHost: x\r\n".utf8)))
        let raw = "GET /123456/file?x=1 HTTP/1.1\r\nHost: 10.0.0.2\r\nRange: bytes=100-\r\n\r\n"
        guard case let .success(request)? = LANTransferRequest.parse(Data(raw.utf8)) else { return XCTFail() }
        XCTAssertEqual(request, LANTransferRequest(method: "GET", path: "/123456/file", range: "bytes=100-"))
        XCTAssertEqual(request.route(code: "123456"), .file)
        XCTAssertEqual(request.route(code: "654321"), .notFound)
    }

    func testRoutes() {
        func route(_ path: String) -> LANTransferRequest.Route {
            LANTransferRequest(method: "GET", path: path, range: nil).route(code: "123456")
        }
        XCTAssertEqual(route("/123456"), .page)
        XCTAssertEqual(route("/123456/"), .page)
        XCTAssertEqual(route("/123456/file"), .file)
        XCTAssertEqual(route("/favicon.ico"), .favicon)
        XCTAssertEqual(route("/"), .notFound)
        XCTAssertEqual(route("/123456/../file"), .notFound)
    }

    func testRejectsMalformedAndOversizedHeads() {
        XCTAssertEqual(LANTransferRequest.parse(Data("NONSENSE\r\n\r\n".utf8)), .failure(.malformed))
        XCTAssertEqual(LANTransferRequest.parse(Data(repeating: 65, count: LANTransfer.maximumRequestHeaderBytes + 1)),
                       .failure(.malformed))
    }

    func testRanges() {
        XCTAssertEqual(LANByteRange.resolve(nil, size: 100), .whole)
        XCTAssertEqual(LANByteRange.resolve("bytes=0-9", size: 100), .partial(lower: 0, upper: 9))
        XCTAssertEqual(LANByteRange.resolve("bytes=90-", size: 100), .partial(lower: 90, upper: 99))
        XCTAssertEqual(LANByteRange.resolve("bytes=90-500", size: 100), .partial(lower: 90, upper: 99))
        XCTAssertEqual(LANByteRange.resolve("bytes=-10", size: 100), .partial(lower: 90, upper: 99))
        XCTAssertEqual(LANByteRange.resolve("bytes=-500", size: 100), .partial(lower: 0, upper: 99))
        XCTAssertEqual(LANByteRange.resolve("bytes=100-", size: 100), .unsatisfiable)
        XCTAssertEqual(LANByteRange.resolve("bytes=0-1,5-6", size: 100), .whole)
        XCTAssertEqual(LANByteRange.resolve("items=0-1", size: 100), .whole)
    }

    func testFileHeadersCarryLengthAndUnicodeName() {
        let whole = String(decoding: LANTransferResponse.fileHead(name: "旅行.dropack", size: 1234, range: .whole), as: UTF8.self)
        XCTAssertTrue(whole.hasPrefix("HTTP/1.1 200 OK\r\n"))
        XCTAssertTrue(whole.contains("Content-Length: 1234\r\n"))
        XCTAssertTrue(whole.contains("filename*=UTF-8''%E6%97%85%E8%A1%8C.dropack"))
        XCTAssertTrue(whole.hasSuffix("\r\n\r\n"))
        let partial = String(decoding: LANTransferResponse.fileHead(name: "a.dropack", size: 100,
            range: .partial(lower: 10, upper: 19)), as: UTF8.self)
        XCTAssertTrue(partial.hasPrefix("HTTP/1.1 206 Partial Content\r\n"))
        XCTAssertTrue(partial.contains("Content-Length: 10\r\n"))
        XCTAssertTrue(partial.contains("Content-Range: bytes 10-19/100\r\n"))
    }

    func testPageEscapesAlbumName() {
        let page = LANTransferResponse.page(name: "<b>&\"", size: "1 MB", download: "Download", hint: "Hint")
        XCTAssertTrue(page.contains("&lt;b&gt;&amp;&quot;"))
        XCTAssertFalse(page.contains("<b>&"))
    }
}
