// ElderShield private warning: a floating window that screen sharing and screen capture
// can't see (sharingType = .none), so a scammer watching the shared screen never reads it.
// Usage: eldershield-warning <title> <body> [--visible-to-capture]   (the flag is for testing only)
import AppKit

let args = CommandLine.arguments
let title = args.count > 1 ? args[1] : "Your money has not been sent."
let body = args.count > 2 ? args[2] : ""
let hiddenFromCapture = !args.contains("--visible-to-capture")

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

final class Closer: NSObject { @objc func close() { NSApp.terminate(nil) } }
let closer = Closer()

let width: CGFloat = 560
let screen = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)

func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
    let l = NSTextField(wrappingLabelWithString: text)
    l.font = .systemFont(ofSize: size, weight: weight)
    l.textColor = color
    l.preferredMaxLayoutWidth = width - 48
    return l
}

let headerText = NSMutableAttributedString(string: "●  ", attributes: [
    .foregroundColor: NSColor.systemRed, .font: NSFont.systemFont(ofSize: 11)])
headerText.append(NSAttributedString(string: "ElderShield · only you can see this", attributes: [
    .foregroundColor: NSColor(red: 0.54, green: 0.55, blue: 0.57, alpha: 1), .font: NSFont.systemFont(ofSize: 13)]))
let header = NSTextField(labelWithAttributedString: headerText)
let heading = label(title, size: 24, weight: .semibold, color: .white)
let text = label(body, size: 17, weight: .regular, color: NSColor(red: 0.93, green: 0.93, blue: 0.95, alpha: 1))
let button = NSButton(title: "Got it — I'm safe", target: closer, action: #selector(Closer.close))
button.bezelStyle = .rounded
button.controlSize = .large
button.keyEquivalent = "\r"

let stack = NSStackView(views: [header, heading, text, button])
stack.orientation = .vertical
stack.alignment = .leading
stack.spacing = 10
stack.edgeInsets = NSEdgeInsets(top: 22, left: 24, bottom: 22, right: 24)
stack.setCustomSpacing(18, after: text)

let card = NSVisualEffectView()
card.material = .hudWindow
card.appearance = NSAppearance(named: .darkAqua)
card.state = .active
card.wantsLayer = true
card.layer?.cornerRadius = 20
card.layer?.masksToBounds = true
card.addSubview(stack)
stack.translatesAutoresizingMaskIntoConstraints = false
NSLayoutConstraint.activate([
    stack.leadingAnchor.constraint(equalTo: card.leadingAnchor),
    stack.trailingAnchor.constraint(equalTo: card.trailingAnchor),
    stack.topAnchor.constraint(equalTo: card.topAnchor),
    stack.bottomAnchor.constraint(equalTo: card.bottomAnchor),
    card.widthAnchor.constraint(equalToConstant: width),
])
card.layoutSubtreeIfNeeded()
let height = card.fittingSize.height

let window = NSWindow(contentRect: NSRect(x: screen.midX - width / 2, y: screen.maxY - height - 24, width: width, height: height),
                      styleMask: [.borderless], backing: .buffered, defer: false)
window.contentView = card
window.isOpaque = false
window.backgroundColor = .clear
window.hasShadow = true
window.level = .statusBar
window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
if hiddenFromCapture { window.sharingType = .none }
window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)
app.run()
