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

    /// Produced by the independent Python encoder in web/tests/make_fixtures.py
    /// (salt 00…0f, nonce prefix 01020304), so all three implementations agree.
    func testDecryptsReferenceVectorFromIndependentEncoder() throws {
        let vector = try XCTUnwrap(Data(base64Encoded: referenceVector, options: .ignoreUnknownCharacters))
        let encrypted = directory.appendingPathComponent("vector.dropack")
        let decrypted = directory.appendingPathComponent("vector-dec.dropack")
        try vector.write(to: encrypted)
        try EncryptedPackage.decrypt(source: encrypted, destination: decrypted, password: "dropack-test")
        XCTAssertEqual(try Data(contentsOf: decrypted), Data((0..<5000).map { UInt8(($0 * 31 + 7) % 256) }))
    }

    private let referenceVector = """
        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
        """

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
