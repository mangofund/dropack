import Foundation

/// Password protection happens around a finished `.dropack`, never inside the
/// packaging journal: the sender encrypts a temporary copy only for sharing, and
/// the receiver decrypts to a local copy that the normal import flow then reads.
@MainActor
final class PackageCryptoController: ObservableObject {
    static let minimumPasswordLength = 6
    private static let safetyMargin: UInt64 = 200 * 1024 * 1024

    /// Canonical stage ("正在加密" / "正在解密") while work runs; nil when idle.
    @Published private(set) var stage: String?
    @Published private(set) var fraction: Double = 0
    private var cancelWork: (() -> Void)?

    var isRunning: Bool { stage != nil }

    static func validationMessage(password: String, confirmation: String) -> String? {
        if password.count < minimumPasswordLength { return "密码至少需要 6 个字符。" }
        if password != confirmation { return "两次输入的密码不一致。" }
        return nil
    }

    func encryptForSharing(_ archive: URL, password: String) async throws -> URL {
        let root = Self.shareRoot
        try? FileManager.default.removeItem(at: root)
        let folder = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let destination = folder.appendingPathComponent(archive.deletingPathExtension().lastPathComponent)
            .appendingPathExtension(PackageFileFormat.dropack.fileExtension)
        try Self.checkSpace(required: PackageRecovery.fileSize(archive), at: folder)
        do {
            try await run(stage: "正在加密") { progress in
                try EncryptedPackage.encrypt(source: archive, destination: destination, password: password, progress: progress)
            }
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
        return destination
    }

    /// Temporary encrypted copies are only needed while the share sheet is open.
    func finishSharing() {
        guard !isRunning else { return }
        try? FileManager.default.removeItem(at: Self.shareRoot)
    }

    /// Checks the password on the first chunk before reserving space for the copy.
    func decryptForImport(_ source: URL, password: String) async throws -> URL {
        try await Task.detached(priority: .userInitiated) {
            try EncryptedPackage.checkPassword(source: source, password: password)
        }.value
        let folder = Self.decryptedRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        var name = source.deletingPathExtension().lastPathComponent
        if name.isEmpty { name = "Dropack" }
        let destination = folder.appendingPathComponent(name).appendingPathExtension(PackageFileFormat.dropack.fileExtension)
        do {
            try Self.checkSpace(required: EncryptedPackage.plaintextSize(source), at: folder)
            try await run(stage: "正在解密") { progress in
                try EncryptedPackage.decrypt(source: source, destination: destination, password: password, progress: progress)
            }
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
        return destination
    }

    /// Removes a decrypted copy that the import flow did not accept.
    func discardDecrypted(_ url: URL) {
        let folder = url.deletingLastPathComponent()
        guard folder.deletingLastPathComponent().standardizedFileURL == Self.decryptedRoot.standardizedFileURL else { return }
        try? FileManager.default.removeItem(at: folder)
    }

    func cancel() { cancelWork?() }

    private func run(stage: String, _ body: @escaping @Sendable (_ progress: (Double) -> Void) throws -> Void) async throws {
        guard !isRunning else { throw CancellationError() }
        self.stage = stage; fraction = 0
        defer { self.stage = nil; cancelWork = nil }
        let job = Task.detached(priority: .userInitiated) { [weak self] in
            var reported = -1.0
            try body { value in
                // Hop to the main actor at most every 0.5% so 30 GB stays cheap.
                guard value - reported >= 0.005 || value >= 1 else { return }
                reported = value
                Task { @MainActor in self?.fraction = value }
            }
        }
        cancelWork = { job.cancel() }
        try await withTaskCancellationHandler { try await job.value } onCancel: { job.cancel() }
    }

    private static func checkSpace(required: UInt64, at directory: URL) throws {
        let values = try directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        let available = UInt64(max(0, values.volumeAvailableCapacityForImportantUsage ?? 0))
        let needed = required.addingClamped(safetyMargin)
        guard available >= needed else { throw PhotoPackageError.insufficientSpace(needed, available) }
    }

    private static var shareRoot: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("EncryptedShares", isDirectory: true)
    }

    private static var decryptedRoot: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("DecryptedPackages", isDirectory: true)
    }
}
