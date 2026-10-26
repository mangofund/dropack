import AVFoundation
import CryptoKit
import Foundation
import ImageIO

public enum LocationMetadataError: Error, LocalizedError, Sendable {
    case unsupported(String)
    public var errorDescription: String? {
        switch self {
        case .unsupported(let name):
            return "无法去除“\(name)”的位置信息。请关闭“去除位置信息”后重试，或从分享相册中移除这一项。"
        }
    }
}

public struct LocationMetadataRemovalResult: Equatable, Sendable {
    public var byteCount: UInt64
    public var hash: String
}

/// Writes a copy without GPS/location metadata. Photo pixels and video samples
/// are copied, never re-encoded, so the receiver still gets the original quality.
/// Other metadata (capture date, Live Photo content identifier) is retained.
public enum LocationMetadataRemoval {
    public static func removeLocation(from source: URL, kind: MediaKind, to destination: URL,
                                      displayName: String) async throws -> LocationMetadataRemovalResult {
        try? FileManager.default.removeItem(at: destination)
        do {
            switch kind {
            case .photo: try removePhotoLocation(from: source, to: destination, displayName: displayName)
            case .video: try await removeVideoLocation(from: source, to: destination, displayName: displayName)
            }
            try Task.checkCancellation()
            return try hash(destination)
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    static func removePhotoLocation(from source: URL, to destination: URL, displayName: String) throws {
        guard let input = CGImageSourceCreateWithURL(source as CFURL, nil),
              let type = CGImageSourceGetType(input), CGImageSourceGetCount(input) > 0,
              let output = CGImageDestinationCreateWithURL(destination as CFURL, type, CGImageSourceGetCount(input), nil) else {
            throw LocationMetadataError.unsupported(displayName)
        }
        // Without explicit metadata the copy drops EXIF/XMP entirely. Merge the
        // primary image's metadata back and let ImageIO exclude only GPS. The
        // result is verified below for every image in the container.
        var options: [CFString: Any] = [kCGImageMetadataShouldExcludeGPS: true]
        if let metadata = CGImageSourceCopyMetadataAtIndex(input, 0, nil) {
            options[kCGImageDestinationMetadata] = metadata
            options[kCGImageDestinationMergeMetadata] = true
        }
        // Copies the encoded image data losslessly; the call finalizes the destination.
        guard CGImageDestinationCopyImageSource(output, input, options as CFDictionary, nil),
              !photoHasLocation(destination) else {
            throw LocationMetadataError.unsupported(displayName)
        }
    }

    public static func photoHasLocation(_ url: URL) -> Bool {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else { return false }
        for index in 0..<CGImageSourceGetCount(source) {
            let properties = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [CFString: Any]
            if properties?[kCGImagePropertyGPSDictionary] != nil { return true }
        }
        return false
    }

    static func removeVideoLocation(from source: URL, to destination: URL, displayName: String) async throws {
        let asset = AVURLAsset(url: source)
        let metadata = try await asset.load(.metadata)
        guard let session = AVAssetExportSession(asset: asset, presetName: AVAssetExportPresetPassthrough) else {
            throw LocationMetadataError.unsupported(displayName)
        }
        let fileType: AVFileType
        switch source.pathExtension.lowercased() {
        case "mp4": fileType = .mp4
        case "m4v": fileType = .m4v
        default: fileType = .mov
        }
        guard session.supportedFileTypes.contains(fileType) else { throw LocationMetadataError.unsupported(displayName) }
        session.outputURL = destination
        session.outputFileType = fileType
        session.metadata = metadata.filter { !isLocation($0) }
        await withTaskCancellationHandler {
            await session.export()
        } onCancel: { session.cancelExport() }
        try Task.checkCancellation()
        guard session.status == .completed else { throw LocationMetadataError.unsupported(displayName) }
        let remaining = try await videoHasLocation(destination)
        guard !remaining else { throw LocationMetadataError.unsupported(displayName) }
    }

    public static func videoHasLocation(_ url: URL) async throws -> Bool {
        let asset = AVURLAsset(url: url)
        if try await asset.load(.metadata).contains(where: isLocation) { return true }
        for track in try await asset.load(.tracks) {
            if try await track.load(.metadata).contains(where: isLocation) { return true }
        }
        return false
    }

    /// QuickTime, user-data, common and 3GP spellings of location and heading.
    static func isLocation(_ item: AVMetadataItem) -> Bool {
        let names = [item.identifier?.rawValue, item.key as? String, item.commonKey?.rawValue]
            .compactMap { $0?.lowercased() }
        return names.contains { name in
            ["location", "%a9xyz", "©xyz", "loci", "direction"].contains { name.contains($0) }
        }
    }

    static func hash(_ url: URL) throws -> LocationMetadataRemovalResult {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        var count: UInt64 = 0
        while true {
            try Task.checkCancellation()
            let chunk: Data? = try autoreleasepool { try handle.read(upToCount: 1024 * 1024) }
            guard let chunk, !chunk.isEmpty else { break }
            hasher.update(data: chunk)
            count += UInt64(chunk.count)
        }
        guard count > 0 else { throw LocationMetadataError.unsupported(url.lastPathComponent) }
        return LocationMetadataRemovalResult(byteCount: count,
            hash: hasher.finalize().map { String(format: "%02x", $0) }.joined())
    }
}
