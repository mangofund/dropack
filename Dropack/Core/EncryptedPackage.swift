import CommonCrypto
import CryptoKit
import Foundation
import Security

public enum EncryptedPackageError: Error, LocalizedError, Equatable, Sendable {
    case wrongPassword, damaged, unsupportedVersion, emptyPassword
    public var errorDescription: String? {
        switch self {
        case .wrongPassword: return "密码不正确，请向发送者确认密码后重试。"
        case .damaged: return "加密照片包不完整或已损坏，请让发送者重新发送。"
        case .unsupportedVersion: return "这个加密照片包需要更新版本的 Dropack 才能打开。"
        case .emptyPassword: return "请输入密码。"
        }
    }
}

/// A password-protected Dropack document: a header followed by the original
/// `.dropack` ZIP split into AES-256-GCM chunks (format v1).
///
///     magic "DROPACKE" | version u8 = 1 | kdf u8 = 1 (PBKDF2-HMAC-SHA256)
///     iterations u32 | salt 16 | chunk size u32 | nonce prefix 4     (38 bytes)
///     repeated: ciphertext (chunk size, shorter for the last) | tag 16
///
/// Chunk n uses nonce = prefix || n (u64), and authenticates header || final flag
/// (u8), so reordering, truncation or appended chunks fail. All integers are
/// big-endian. Browsers can decrypt the same layout with WebCrypto.
public enum EncryptedPackage {
    public static let magic = Data("DROPACKE".utf8)
    public static let headerSize = 38
    public static let tagSize = 16
    public static let defaultIterations: UInt32 = 600_000
    public static let defaultChunkSize: UInt32 = 1024 * 1024

    struct Header: Equatable {
        var iterations: UInt32
        var salt: Data
        var chunkSize: UInt32
        var noncePrefix: Data

        var encoded: Data {
            var data = EncryptedPackage.magic
            data.append(contentsOf: [1, 1])
            data.append(bigEndian: iterations)
            data.append(salt)
            data.append(bigEndian: chunkSize)
            data.append(noncePrefix)
            return data
        }

        init(iterations: UInt32, salt: Data, chunkSize: UInt32, noncePrefix: Data) {
            self.iterations = iterations; self.salt = salt; self.chunkSize = chunkSize; self.noncePrefix = noncePrefix
        }

        init(_ data: Data) throws {
            let bytes = [UInt8](data)
            guard bytes.count == EncryptedPackage.headerSize, Data(bytes[0..<8]) == EncryptedPackage.magic else {
                throw EncryptedPackageError.damaged
            }
            guard bytes[8] == 1, bytes[9] == 1 else { throw EncryptedPackageError.unsupportedVersion }
            iterations = UInt32(bigEndian: bytes, at: 10)
            salt = Data(bytes[14..<30])
            chunkSize = UInt32(bigEndian: bytes, at: 30)
            noncePrefix = Data(bytes[34..<38])
            guard (10_000...10_000_000).contains(iterations), (4096...(64 * 1024 * 1024)).contains(chunkSize) else {
                throw EncryptedPackageError.damaged
            }
        }
    }

    /// Reads only the magic bytes; never needs a password.
    public static func isEncrypted(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: magic.count)) == magic
    }

    public static func encrypt(source: URL, destination: URL, password: String,
                               iterations: UInt32 = defaultIterations, chunkSize: UInt32 = defaultChunkSize,
                               progress: (Double) -> Void = { _ in }) throws {
        guard !password.isEmpty else { throw EncryptedPackageError.emptyPassword }
        let header = Header(iterations: iterations, salt: randomData(16), chunkSize: chunkSize, noncePrefix: randomData(4))
        let key = try deriveKey(password: password, header: header)
        let headerData = header.encoded
        let total = try PackageRecovery.fileSize(source)
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = try createOutput(destination)
        do {
            try output.write(contentsOf: headerData)
            var index: UInt64 = 0
            var consumed: UInt64 = 0
            repeat {
                try Task.checkCancellation()
                try autoreleasepool {
                    let chunk = try input.read(upToCount: Int(chunkSize)) ?? Data()
                    consumed += UInt64(chunk.count)
                    let isFinal = consumed >= total
                    let sealed = try AES.GCM.seal(chunk, using: key, nonce: nonce(header.noncePrefix, index),
                                                  authenticating: aad(headerData, isFinal: isFinal))
                    try output.write(contentsOf: sealed.ciphertext)
                    try output.write(contentsOf: sealed.tag)
                }
                index += 1
                progress(total == 0 ? 1 : Double(consumed) / Double(total))
            } while consumed < total
            try output.synchronize()
            try output.close()
        } catch {
            try? output.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    /// Verifies the password against the first chunk without writing anything.
    public static func checkPassword(source: URL, password: String) throws {
        try decrypt(source: source, destination: nil, password: password, firstChunkOnly: true)
    }

    public static func decrypt(source: URL, destination: URL, password: String,
                               progress: (Double) -> Void = { _ in }) throws {
        try decrypt(source: source, destination: Optional(destination), password: password, progress: progress)
    }

    private static func decrypt(source: URL, destination: URL?, password: String, firstChunkOnly: Bool = false,
                                progress: (Double) -> Void = { _ in }) throws {
        guard !password.isEmpty else { throw EncryptedPackageError.emptyPassword }
        let total = try PackageRecovery.fileSize(source)
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        guard let headerData = try input.read(upToCount: headerSize), headerData.count == headerSize else {
            throw EncryptedPackageError.damaged
        }
        let header = try Header(headerData)
        let key = try deriveKey(password: password, header: header)
        let sealedSize = UInt64(header.chunkSize) + UInt64(tagSize)
        let body = total - UInt64(headerSize)
        guard body >= UInt64(tagSize) else { throw EncryptedPackageError.damaged }
        let output = try destination.map(createOutput)
        do {
            var index: UInt64 = 0
            var consumed: UInt64 = 0
            while consumed < body {
                try Task.checkCancellation()
                try autoreleasepool {
                    let remaining = body - consumed
                    let size = Int(min(remaining, sealedSize))
                    guard size >= tagSize, let sealed = try input.read(upToCount: size), sealed.count == size else {
                        throw EncryptedPackageError.damaged
                    }
                    consumed += UInt64(size)
                    let isFinal = consumed == body
                    let box = try AES.GCM.SealedBox(nonce: nonce(header.noncePrefix, index),
                        ciphertext: sealed.prefix(size - tagSize), tag: sealed.suffix(tagSize))
                    let plain: Data
                    do { plain = try AES.GCM.open(box, using: key, authenticating: aad(headerData, isFinal: isFinal)) }
                    catch { throw index == 0 ? EncryptedPackageError.wrongPassword : EncryptedPackageError.damaged }
                    try output?.write(contentsOf: plain)
                }
                index += 1
                progress(Double(consumed) / Double(body))
                if firstChunkOnly { break }
            }
            try output?.synchronize()
            try output?.close()
        } catch {
            try? output?.close()
            if let destination { try? FileManager.default.removeItem(at: destination) }
            throw error
        }
    }

    /// Plaintext size, used to reserve disk space before decrypting.
    public static func plaintextSize(_ url: URL) throws -> UInt64 {
        let total = try PackageRecovery.fileSize(url)
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        guard let headerData = try input.read(upToCount: headerSize), headerData.count == headerSize else {
            throw EncryptedPackageError.damaged
        }
        let header = try Header(headerData)
        let body = total - UInt64(headerSize)
        let sealedSize = UInt64(header.chunkSize) + UInt64(tagSize)
        let chunks = (body + sealedSize - 1) / sealedSize
        guard chunks > 0, body >= chunks * UInt64(tagSize) else { throw EncryptedPackageError.damaged }
        return body - chunks * UInt64(tagSize)
    }

    static func deriveKey(password: String, header: Header) throws -> SymmetricKey {
        let passwordData = Data(password.precomposedStringWithCanonicalMapping.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        let status = passwordData.withUnsafeBytes { passwordBytes in
            header.salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.bindMemory(to: CChar.self).baseAddress, passwordData.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress, header.salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), header.iterations, &derived, derived.count)
            }
        }
        guard status == kCCSuccess else { throw EncryptedPackageError.damaged }
        return SymmetricKey(data: derived)
    }

    private static func nonce(_ prefix: Data, _ index: UInt64) throws -> AES.GCM.Nonce {
        var data = prefix
        data.append(bigEndian: index)
        return try AES.GCM.Nonce(data: data)
    }

    private static func aad(_ header: Data, isFinal: Bool) -> Data {
        var data = header
        data.append(isFinal ? 1 : 0)
        return data
    }

    private static func randomData(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            return Data(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0.prefix(count)) })
        }
        return Data(bytes)
    }

    private static func createOutput(_ url: URL) throws -> FileHandle {
        try? FileManager.default.removeItem(at: url)
        guard FileManager.default.createFile(atPath: url.path, contents: nil) else { throw EncryptedPackageError.damaged }
        return try FileHandle(forWritingTo: url)
    }
}

private extension Data {
    mutating func append<T: FixedWidthInteger>(bigEndian value: T) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
}

private extension UInt32 {
    init(bigEndian bytes: [UInt8], at offset: Int) {
        self = bytes[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }
}
