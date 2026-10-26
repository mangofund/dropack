import AVFoundation
import CoreGraphics
import CryptoKit
import ImageIO
import UniformTypeIdentifiers
import XCTest
@testable import RelayCore

final class LocationMetadataRemovalTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: directory) }

    func testPhotoKeepsPixelsAndDateButDropsGPS() async throws {
        let source = directory.appendingPathComponent("photo.jpg")
        try writeJPEGWithLocation(to: source)
        XCTAssertTrue(LocationMetadataRemoval.photoHasLocation(source))

        let output = directory.appendingPathComponent("clean.jpg")
        let result = try await LocationMetadataRemoval.removeLocation(from: source, kind: .photo, to: output, displayName: "photo.jpg")

        XCTAssertFalse(LocationMetadataRemoval.photoHasLocation(output))
        let data = try Data(contentsOf: output)
        XCTAssertEqual(result.byteCount, UInt64(data.count))
        XCTAssertEqual(result.hash, SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
        let exif = properties(output)[kCGImagePropertyExifDictionary] as? [CFString: Any]
        XCTAssertEqual(exif?[kCGImagePropertyExifDateTimeOriginal] as? String, "2026:10:01 12:34:56")
        XCTAssertEqual(try pixels(source), try pixels(output))
    }

    func testUnreadablePhotoFailsWithoutLeavingOutput() async throws {
        let source = directory.appendingPathComponent("broken.jpg")
        try Data("not an image".utf8).write(to: source)
        let output = directory.appendingPathComponent("clean.jpg")
        do {
            _ = try await LocationMetadataRemoval.removeLocation(from: source, kind: .photo, to: output, displayName: "broken.jpg")
            XCTFail("expected failure")
        } catch LocationMetadataError.unsupported(let name) {
            XCTAssertEqual(name, "broken.jpg")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testVideoDropsLocationAndKeepsLivePhotoIdentifier() async throws {
        let source = directory.appendingPathComponent("video.mov")
        try await writeMovieWithLocation(to: source, contentIdentifier: "D7A1F2C4-LIVE")
        let hasSourceLocation = try await LocationMetadataRemoval.videoHasLocation(source)
        XCTAssertTrue(hasSourceLocation)

        let output = directory.appendingPathComponent("clean.mov")
        _ = try await LocationMetadataRemoval.removeLocation(from: source, kind: .video, to: output, displayName: "video.mov")

        let hasOutputLocation = try await LocationMetadataRemoval.videoHasLocation(output)
        XCTAssertFalse(hasOutputLocation)
        let asset = AVURLAsset(url: output)
        let metadata = try await asset.load(.metadata)
        let identifier = metadata.first { $0.identifier == .quickTimeMetadataContentIdentifier }
        let value = try await identifier?.load(.stringValue)
        XCTAssertEqual(value, "D7A1F2C4-LIVE")
        let sourceTracks = try await AVURLAsset(url: source).load(.tracks)
        let outputTracks = try await asset.load(.tracks)
        XCTAssertEqual(outputTracks.count, sourceTracks.count)
    }

    func testRecognizesLocationKeysAcrossKeySpaces() {
        let location = AVMutableMetadataItem()
        location.identifier = .quickTimeUserDataLocationISO6709
        location.value = "+35.0000+139.0000/" as NSString
        let date = AVMutableMetadataItem()
        date.identifier = .quickTimeMetadataCreationDate
        date.value = "2026-10-01T12:34:56+0900" as NSString
        XCTAssertTrue(LocationMetadataRemoval.isLocation(location))
        XCTAssertFalse(LocationMetadataRemoval.isLocation(date))
    }

    // MARK: - Fixtures

    private func writeJPEGWithLocation(to url: URL) throws {
        let width = 16, height = 16
        let context = try XCTUnwrap(CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue))
        context.setFillColor(red: 0.2, green: 0.6, blue: 0.9, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let image = try XCTUnwrap(context.makeImage())
        let destination = try XCTUnwrap(CGImageDestinationCreateWithURL(url as CFURL, UTType.jpeg.identifier as CFString, 1, nil))
        let properties: [CFString: Any] = [
            kCGImagePropertyGPSDictionary: [kCGImagePropertyGPSLatitude: 35.6586, kCGImagePropertyGPSLatitudeRef: "N",
                                            kCGImagePropertyGPSLongitude: 139.7454, kCGImagePropertyGPSLongitudeRef: "E"],
            kCGImagePropertyExifDictionary: [kCGImagePropertyExifDateTimeOriginal: "2026:10:01 12:34:56"]
        ]
        CGImageDestinationAddImage(destination, image, properties as CFDictionary)
        XCTAssertTrue(CGImageDestinationFinalize(destination))
    }

    private func properties(_ url: URL) -> [CFString: Any] {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else { return [:] }
        return CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] ?? [:]
    }

    private func pixels(_ url: URL) throws -> Data {
        let source = try XCTUnwrap(CGImageSourceCreateWithURL(url as CFURL, nil))
        let image = try XCTUnwrap(CGImageSourceCreateImageAtIndex(source, 0, nil))
        return try XCTUnwrap(image.dataProvider?.data as Data?)
    }

    private func writeMovieWithLocation(to url: URL, contentIdentifier: String) async throws {
        let writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        let location = AVMutableMetadataItem()
        location.identifier = .quickTimeMetadataLocationISO6709
        location.value = "+35.6586+139.7454/" as NSString
        location.dataType = kCMMetadataBaseDataType_UTF8 as String
        let identifier = AVMutableMetadataItem()
        identifier.identifier = .quickTimeMetadataContentIdentifier
        identifier.value = contentIdentifier as NSString
        identifier.dataType = kCMMetadataBaseDataType_UTF8 as String
        writer.metadata = [location, identifier]
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
            AVVideoCodecKey: AVVideoCodecType.h264, AVVideoWidthKey: 64, AVVideoHeightKey: 64])
        input.expectsMediaDataInRealTime = false
        let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: 64, kCVPixelBufferHeightKey as String: 64])
        writer.add(input)
        XCTAssertTrue(writer.startWriting())
        writer.startSession(atSourceTime: .zero)
        for frame in 0..<10 {
            while !input.isReadyForMoreMediaData { try await Task.sleep(nanoseconds: 1_000_000) }
            let pool = try XCTUnwrap(adaptor.pixelBufferPool)
            var buffer: CVPixelBuffer?
            CVPixelBufferPoolCreatePixelBuffer(nil, pool, &buffer)
            let pixelBuffer = try XCTUnwrap(buffer)
            CVPixelBufferLockBaseAddress(pixelBuffer, [])
            memset(CVPixelBufferGetBaseAddress(pixelBuffer), Int32(frame * 20), CVPixelBufferGetDataSize(pixelBuffer))
            CVPixelBufferUnlockBaseAddress(pixelBuffer, [])
            XCTAssertTrue(adaptor.append(pixelBuffer, withPresentationTime: CMTime(value: CMTimeValue(frame), timescale: 30)))
        }
        input.markAsFinished()
        await writer.finishWriting()
        XCTAssertEqual(writer.status, .completed, writer.error?.localizedDescription ?? "")
    }
}
