import XCTest
@testable import RelayCore

final class EncryptedPackageTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: directory) }

    func testRoundTripsAcrossChunkBoundaries() throws {
        for size in [0, 1, 4095, 4096, 4097, 3 * 4096, 20_000] {
            let plain = randomBytes(size)
            let (source, encrypted, decrypted) = try urls(plain, name: "\(size)")
            try EncryptedPackage.encrypt(source: source, destination: encrypted, password: "correct horse",
                                         iterations: 10_000, chunkSize: 4096)
            XCTAssertTrue(EncryptedPackage.isEncrypted(encrypted))
            XCTAssertFalse(EncryptedPackage.isEncrypted(source))
            XCTAssertEqual(try EncryptedPackage.plaintextSize(encrypted), UInt64(size))
            try EncryptedPackage.checkPassword(source: encrypted, password: "correct horse")
            try EncryptedPackage.decrypt(source: encrypted, destination: decrypted, password: "correct horse")
            XCTAssertEqual(try Data(contentsOf: decrypted), plain, "size \(size)")
        }
    }

    func testWrongPasswordIsReportedAndLeavesNoOutput() throws {
        let (source, encrypted, decrypted) = try urls(randomBytes(10_000), name: "wrong")
        try EncryptedPackage.encrypt(source: source, destination: encrypted, password: "secret1",
                                     iterations: 10_000, chunkSize: 4096)
        XCTAssertThrowsError(try EncryptedPackage.checkPassword(source: encrypted, password: "secret2")) {
            XCTAssertEqual($0 as? EncryptedPackageError, .wrongPassword)
        }
        XCTAssertThrowsError(try EncryptedPackage.decrypt(source: encrypted, destination: decrypted, password: "secret2")) {
            XCTAssertEqual($0 as? EncryptedPackageError, .wrongPassword)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: decrypted.path))
    }

    func testTamperingTruncationAndReorderingAreDetected() throws {
        let (source, encrypted, decrypted) = try urls(randomBytes(3 * 4096 + 10), name: "tamper")
        try EncryptedPackage.encrypt(source: source, destination: encrypted, password: "secret1",
                                     iterations: 10_000, chunkSize: 4096)
        let original = try Data(contentsOf: encrypted)
        let sealed = 4096 + EncryptedPackage.tagSize
        let header = EncryptedPackage.headerSize

        var flipped = original
        flipped[header + sealed + 7] ^= 0x01
        var truncated = original
        truncated.removeLast(10 + EncryptedPackage.tagSize)
        var swapped = original
        swapped.replaceSubrange(header..<header + sealed, with: original[header + sealed..<header + 2 * sealed])
        swapped.replaceSubrange(header + sealed..<header + 2 * sealed, with: original[header..<header + sealed])

        for (name, data) in [("flipped", flipped), ("truncated", truncated), ("swapped", swapped)] {
            try data.write(to: encrypted)
            XCTAssertThrowsError(try EncryptedPackage.decrypt(source: encrypted, destination: decrypted, password: "secret1"), name) {
                XCTAssertNotNil($0 as? EncryptedPackageError, name)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: decrypted.path), name)
        }
    }

    func testRejectsEmptyPasswordAndUnknownVersion() throws {
        let (source, encrypted, decrypted) = try urls(randomBytes(100), name: "version")
        XCTAssertThrowsError(try EncryptedPackage.encrypt(source: source, destination: encrypted, password: "")) {
            XCTAssertEqual($0 as? EncryptedPackageError, .emptyPassword)
        }
        try EncryptedPackage.encrypt(source: source, destination: encrypted, password: "secret1",
                                     iterations: 10_000, chunkSize: 4096)
        var data = try Data(contentsOf: encrypted)
        data[8] = 2
        try data.write(to: encrypted)
        XCTAssertThrowsError(try EncryptedPackage.decrypt(source: encrypted, destination: decrypted, password: "secret1")) {
            XCTAssertEqual($0 as? EncryptedPackageError, .unsupportedVersion)
        }
    }

    func testDefaultParametersUseStrongKeyDerivation() {
        XCTAssertGreaterThanOrEqual(EncryptedPackage.defaultIterations, 600_000)
        XCTAssertEqual(EncryptedPackage.defaultChunkSize, 1024 * 1024)
    }

    private func urls(_ plain: Data, name: String) throws -> (URL, URL, URL) {
        let source = directory.appendingPathComponent("\(name).dropack")
        try plain.write(to: source)
        return (source, directory.appendingPathComponent("\(name)-enc.dropack"),
                directory.appendingPathComponent("\(name)-dec.dropack"))
    }

    private func randomBytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }
}
