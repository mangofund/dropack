import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct LANShareRequest: Identifiable {
    let id = UUID()
    let url: URL
    let title: String
}

/// Shows the address, QR code and receive code while this device serves the package.
struct LANShareView: View {
    @ObservedObject private var localizationPreferences = AppPreferences.shared
    @StateObject private var server: LANShareController
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    init(request: LANShareRequest) {
        _server = StateObject(wrappedValue: LANShareController(fileURL: request.url, title: request.title))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text(server.title).font(.title3.weight(.semibold))
                    switch server.phase {
                    case .starting:
                        ProgressView(L10n.tr("正在开启局域网共享…"))
                    case let .ready(url):
                        ready(url)
                    case .noNetwork:
                        problem(L10n.tr("没有连接 Wi-Fi。请连接 Wi-Fi 或打开个人热点，让接收方连到同一个网络。"))
                    case let .failed(message):
                        problem(L10n.tr(message))
                    }
                    Label(L10n.tr("文件直接从这台设备传给对方，不经过网络服务器。共享期间请保持此页面打开、屏幕常亮。"),
                          systemImage: "lock.shield")
                        .font(.footnote).foregroundStyle(RelayTheme.secondary)
                }
                .padding(20)
                .frame(maxWidth: 520, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            .background(RelayTheme.background)
            .navigationTitle(L10n.tr("局域网直传"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button(L10n.tr("完成")) { dismiss() } } }
        }
        .tint(RelayTheme.accent)
        .onAppear { server.start() }
        .onDisappear { server.stop() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { server.sceneDidBecomeActive() }
        }
    }

    private func ready(_ url: URL) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text(L10n.tr("接收码")).font(.caption.weight(.semibold)).foregroundStyle(RelayTheme.secondary)
                Text(server.code.map(String.init).joined(separator: " "))
                    .font(.system(size: 40, weight: .semibold, design: .rounded)).monospacedDigit()
                    .accessibilityIdentifier("lanShareCode")
                Text(L10n.tr("对方在 Dropack 里点“从局域网接收”，选择这台设备并输入接收码。"))
                    .font(.footnote).foregroundStyle(RelayTheme.secondary)
            }
            .padding(18).frame(maxWidth: .infinity, alignment: .leading)
            .background(RelayTheme.surface, in: RoundedRectangle(cornerRadius: 18))

            VStack(spacing: 12) {
                if let image = QRCode.image(for: url.absoluteString) {
                    Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
                        .frame(maxWidth: 220).padding(12)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
                        .accessibilityLabel(L10n.tr("二维码"))
                }
                Text(url.absoluteString).font(.callout.monospaced()).textSelection(.enabled)
                    .multilineTextAlignment(.center)
                Text(L10n.tr("没有 Dropack 的设备（电脑、安卓）连同一个 Wi-Fi 后，扫码或在浏览器输入这个地址即可下载。"))
                    .font(.footnote).foregroundStyle(RelayTheme.secondary).multilineTextAlignment(.center)
            }
            .padding(18).frame(maxWidth: .infinity)
            .background(RelayTheme.surface, in: RoundedRectangle(cornerRadius: 18))

            status
        }
    }

    @ViewBuilder private var status: some View {
        if server.activeDownloads > 0 {
            let sent = ByteCountFormatter.string(fromByteCount: Int64(clamping: server.sentBytes), countStyle: .file)
            let total = ByteCountFormatter.string(fromByteCount: Int64(clamping: server.fileSize), countStyle: .file)
            VStack(alignment: .leading, spacing: 8) {
                Label(L10n.tr("正在发送 %@ / %@", sent, total), systemImage: "arrow.up.circle")
                    .font(.subheadline.weight(.medium))
                if server.fileSize > 0 {
                    ProgressView(value: min(1, Double(server.sentBytes) / Double(server.fileSize)))
                }
            }
        } else if server.completedDownloads > 0 {
            Label(L10n.tr("已发送 %@ 次", String(server.completedDownloads)), systemImage: "checkmark.circle")
                .font(.subheadline.weight(.medium)).foregroundStyle(RelayTheme.accent)
        } else {
            Label(L10n.tr("等待对方接收…"), systemImage: "wifi").font(.subheadline)
        }
    }

    private func problem(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(message, systemImage: "exclamationmark.triangle").font(.subheadline)
                .foregroundStyle(RelayTheme.warning)
            Button(L10n.tr("重试")) { server.start() }
        }
    }
}

/// Lists nearby senders and downloads one package with its receive code.
struct LANReceiveView: View {
    @ObservedObject private var localizationPreferences = AppPreferences.shared
    @StateObject private var receiver = LANReceiveController()
    @Environment(\.dismiss) private var dismiss
    @State private var selected: LANReceiveController.Sender?
    @State private var code = ""
    var onReceived: (URL) -> Void

    var body: some View {
        NavigationStack {
            List {
                if case let .downloading(name) = receiver.phase {
                    Section {
                        VStack(alignment: .leading, spacing: 10) {
                            Text(L10n.tr("正在接收 %@", name)).font(.subheadline.weight(.medium))
                            ProgressView(value: receiver.fraction)
                            Button(L10n.tr("取消"), role: .cancel) { receiver.cancelDownload() }
                        }
                    }
                }
                if case let .failed(message) = receiver.phase {
                    Section {
                        Label(L10n.tr(message), systemImage: "exclamationmark.triangle")
                            .foregroundStyle(RelayTheme.warning)
                    }
                }
                if receiver.permissionProblem {
                    Section {
                        Text(L10n.tr("Dropack 没有本地网络权限。请在“设置 > 隐私与安全性 > 本地网络”中打开 Dropack。"))
                            .foregroundStyle(RelayTheme.warning)
                    }
                }
                Section {
                    if receiver.senders.isEmpty {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text(L10n.tr("正在寻找附近的发送方…")).foregroundStyle(RelayTheme.secondary)
                        }
                    }
                    ForEach(receiver.senders) { sender in
                        Button {
                            receiver.clearFailure()
                            code = ""
                            selected = sender
                        } label: {
                            HStack {
                                Image(systemName: "iphone.radiowaves.left.and.right").foregroundStyle(RelayTheme.accent)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(sender.name).foregroundStyle(RelayTheme.ink)
                                    if let size = sender.size {
                                        Text(ByteCountFormatter.string(fromByteCount: Int64(clamping: size), countStyle: .file))
                                            .font(.footnote).foregroundStyle(RelayTheme.secondary)
                                    }
                                }
                            }
                        }
                        .disabled(isDownloading)
                    }
                } header: {
                    Text(L10n.tr("附近的发送方"))
                } footer: {
                    Text(L10n.tr("发送方在相册菜单里选择“局域网直传…”，两台设备连同一个 Wi-Fi。"))
                }
            }
            .navigationTitle(L10n.tr("从局域网接收"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button(L10n.tr("完成")) { dismiss() } } }
            .alert(L10n.tr("输入接收码"), isPresented: Binding(get: { selected != nil }, set: { if !$0 { selected = nil } })) {
                TextField(L10n.tr("6 位数字"), text: $code).keyboardType(.numberPad)
                Button(L10n.tr("接收")) { receive() }
                Button(L10n.tr("取消"), role: .cancel) { selected = nil }
            } message: { Text(L10n.tr("接收码显示在发送方的屏幕上。")) }
        }
        .tint(RelayTheme.accent)
        .onAppear { receiver.startBrowsing() }
        .onDisappear { receiver.stop() }
    }

    private var isDownloading: Bool {
        if case .downloading = receiver.phase { return true }
        return false
    }

    private func receive() {
        guard let sender = selected else { return }
        selected = nil
        let entered = code.filter(\.isNumber)
        Task {
            if let file = await receiver.download(from: sender, code: entered) { onReceived(file) }
        }
    }
}

enum QRCode {
    static func image(for text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cgImage = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
