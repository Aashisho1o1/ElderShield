// ElderShield listener: hears the call and turns it into text, on this Mac.
//
// Taps all system audio (everything except this program) with a Core Audio process tap
// (macOS 14.2+), so it hears the other side of a FaceTime/phone/WhatsApp call, and runs
// Apple's on-device speech recognizer on it. Nothing is saved here.
//
//   Test:   macos/capture-test.sh [--seconds 20]       prints a level meter and the transcript
//   Speech is transcribed on this Mac. If the on-device model is missing, it says so and doesn't
//   transcribe, unless --allow-cloud lets Apple's servers do it.
//   Listen: started by device_watch.py --listen with --post http://127.0.0.1:8777/calls/transcript;
//           sends text in ~15 s chunks while the call lasts. The daemon keeps only warning-sign
//           labels and the flagged sentence.
//
// Permissions it will ask for: System Audio Recording, Speech Recognition.
import AVFoundation
import CoreAudio
import Foundation
import Speech

setvbuf(stdout, nil, _IONBF, 0)   // show progress even when piped

func arg(_ name: String) -> String? {
    let a = CommandLine.arguments
    if let i = a.firstIndex(of: name), i + 1 < a.count { return a[i + 1] }
    return nil
}
let postURL = arg("--post").flatMap(URL.init(string:))
let seconds = postURL == nil ? Int(arg("--seconds") ?? "") ?? 20 : Int.max
let allowCloud = CommandLine.arguments.contains("--allow-cloud")
// Launched with `open` (so macOS attributes the permission prompts to this app, not the
// terminal), stdout goes nowhere; the caller tails this file instead.
let logFile: FileHandle? = arg("--log").flatMap { path in
    FileManager.default.createFile(atPath: path, contents: nil)
    return FileHandle(forWritingAtPath: path)
}
func out(_ line: String) {
    print(line)
    logFile?.write((line + "\n").data(using: .utf8)!)
}

func check(_ status: OSStatus, _ what: String) {
    if status != noErr {
        out("✗ \(what) failed (OSStatus \(status)). If this is a permission problem, allow it under "
            + "System Settings → Privacy & Security → Screen & System Audio Recording, then run again.")
        exit(1)
    }
}

func address(_ selector: AudioObjectPropertySelector) -> AudioObjectPropertyAddress {
    AudioObjectPropertyAddress(mSelector: selector, mScope: kAudioObjectPropertyScopeGlobal,
                               mElement: kAudioObjectPropertyElementMain)
}

func get<T>(_ obj: AudioObjectID, _ selector: AudioObjectPropertySelector, _ value: inout T) -> OSStatus {
    var addr = address(selector)
    var size = UInt32(MemoryLayout<T>.size)
    return withUnsafeMutablePointer(to: &value) { AudioObjectGetPropertyData(obj, &addr, 0, nil, &size, $0) }
}

func getList(_ obj: AudioObjectID, _ selector: AudioObjectPropertySelector) -> [AudioObjectID] {
    var addr = address(selector)
    var size: UInt32 = 0
    guard AudioObjectGetPropertyDataSize(obj, &addr, 0, nil, &size) == noErr else { return [] }
    var list = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
    guard AudioObjectGetPropertyData(obj, &addr, 0, nil, &size, &list) == noErr else { return [] }
    return list
}

var nameCache: [pid_t: String] = [:]
func processName(_ pid: pid_t) -> String {
    if let n = nameCache[pid] { return n }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/ps")
    p.arguments = ["-o", "comm=", "-p", String(pid)]
    let pipe = Pipe()
    p.standardOutput = pipe
    try? p.run()
    p.waitUntilExit()
    let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let name = (text.trimmingCharacters(in: .whitespacesAndNewlines) as NSString).lastPathComponent
    nameCache[pid] = name.isEmpty ? "pid \(pid)" : name
    return nameCache[pid]!
}

/// Processes currently producing audio output, by name (not counting this one).
func soundingProcesses() -> [String] {
    var names: [String] = []
    for obj in getList(AudioObjectID(kAudioObjectSystemObject), kAudioHardwarePropertyProcessObjectList) {
        var running: UInt32 = 0
        var pid: pid_t = 0
        guard get(obj, kAudioProcessPropertyIsRunningOutput, &running) == noErr, running != 0,
              get(obj, kAudioProcessPropertyPID, &pid) == noErr, pid != getpid() else { continue }
        names.append(processName(pid))
    }
    return names.sorted()
}

// --- speech: recognition restarts every 15 s, each run is one chunk -----------------------
let recognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US"))
var request: SFSpeechAudioBufferRecognitionRequest?
var chunk = 0
var transcript = ""            // the latest non-empty text, for the test summary
var lastPost: [Int: Date] = [:]

func send(_ chunk: Int, _ text: String, final: Bool) {
    guard let url = postURL else { return }
    if !final, let t = lastPost[chunk], Date().timeIntervalSince(t) < 0.8 { return }   // throttle partials
    lastPost[chunk] = Date()
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.httpBody = try? JSONSerialization.data(withJSONObject: ["chunk": chunk, "text": text])
    URLSession.shared.dataTask(with: req).resume()
}

var transcribing = false        // set once we know where speech will be transcribed

// Words the scam check looks for. Hinting them makes the recognizer more likely to hear them
// right ("AnyDesk", not "any desk"). Keep in step with LEXICON in server.py.
let hints = ["AnyDesk", "TeamViewer", "remote access", "screen share", "install this app",
             "gift card", "gift cards", "Target gift cards", "iTunes card", "Apple card", "Google Play card",
             "read me the numbers", "Western Union", "wire", "wire transfer", "send money", "lend me",
             "customs", "hospital", "plane ticket", "pay the fee", "bitcoin", "crypto", "USDT",
             "trading platform", "guaranteed return", "verification code", "one-time code", "six-digit code",
             "read me the code", "don't tell", "keep this between us", "our secret", "my love", "sweetheart",
             "darling", "soulmate", "marry you", "oil rig", "deployed", "camera is broken", "account is frozen",
             "warrant", "arrested"]

func newChunk() {
    guard let recognizer, transcribing else { return }
    chunk += 1
    let mine = chunk
    let req = SFSpeechAudioBufferRecognitionRequest()
    req.shouldReportPartialResults = true
    req.contextualStrings = hints
    req.requiresOnDeviceRecognition = recognizer.supportsOnDeviceRecognition
    let previous = request
    request = req                      // new audio goes to the new chunk from here on
    previous?.endAudio()
    recognizer.recognitionTask(with: req) { result, error in
        // The recognizer sends an empty final result after the audio ends; keep the words.
        if let r = result, !r.bestTranscription.formattedString.isEmpty {
            let text = r.bestTranscription.formattedString
            if text != transcript {
                transcript = text
                if postURL == nil { out("  transcript: \(text)") }
            }
            send(mine, text, final: r.isFinal)
        }
        if let e = error as NSError?, e.code != 216, e.code != 1110 {   // 216/1110: cancelled / no speech
            out("  speech: \(e.localizedDescription)")
        }
    }
}

// --- capture --------------------------------------------------------------------------
var peak: Float = 0             // loudest moment, for the test result
var level: Float = 0            // loudest moment in the last second, for the meter
var termSource: DispatchSourceSignal?   // global: a local would be released and SIGTERM ignored

func startCapture() {
    let desc = CATapDescription(stereoGlobalTapButExcludeProcesses: [])
    desc.name = "ElderShield listener"
    desc.isPrivate = true
    desc.muteBehavior = .unmuted
    var tap = AudioObjectID(kAudioObjectUnknown)
    check(AudioHardwareCreateProcessTap(desc, &tap), "create system audio tap")

    var outDevice = AudioObjectID(kAudioObjectUnknown)
    check(get(AudioObjectID(kAudioObjectSystemObject), kAudioHardwarePropertyDefaultOutputDevice, &outDevice), "default output")
    var outUID: CFString = "" as CFString
    check(get(outDevice, kAudioDevicePropertyDeviceUID, &outUID), "output UID")

    let aggDesc: [String: Any] = [
        kAudioAggregateDeviceNameKey: "ElderShield listener",
        kAudioAggregateDeviceUIDKey: UUID().uuidString,
        kAudioAggregateDeviceIsPrivateKey: true,
        kAudioAggregateDeviceMainSubDeviceKey: outUID,
        kAudioAggregateDeviceSubDeviceListKey: [[kAudioSubDeviceUIDKey: outUID]],
        kAudioAggregateDeviceTapAutoStartKey: true,
        kAudioAggregateDeviceTapListKey: [[kAudioSubTapUIDKey: desc.uuid.uuidString,
                                           kAudioSubTapDriftCompensationKey: true]],
    ]
    var agg = AudioObjectID(kAudioObjectUnknown)
    check(AudioHardwareCreateAggregateDevice(aggDesc as CFDictionary, &agg), "create aggregate device")

    var asbd = AudioStreamBasicDescription()
    check(get(tap, kAudioTapPropertyFormat, &asbd), "tap format")
    guard let format = AVAudioFormat(streamDescription: &asbd) else { out("✗ bad tap format"); exit(1) }
    out("✓ tapping system audio: \(Int(format.sampleRate)) Hz, \(format.channelCount) ch")

    var proc: AudioDeviceIOProcID?
    check(AudioDeviceCreateIOProcIDWithBlock(&proc, agg, nil) { _, inData, _, _, _ in
        guard let buf = AVAudioPCMBuffer(pcmFormat: format, bufferListNoCopy: inData, deallocator: nil),
              let ch = buf.floatChannelData?[0], buf.frameLength > 0 else { return }
        var sum: Float = 0
        for i in 0..<Int(buf.frameLength) { sum += ch[i] * ch[i] }
        let rms = (sum / Float(buf.frameLength)).squareRoot()
        peak = max(peak, rms)
        level = max(level, rms)
        request?.append(buf)
    }, "create IO proc")
    check(AudioDeviceStart(agg, proc), "start capture")

    let stop = {
        request?.endAudio()
        AudioDeviceStop(agg, proc)
        AudioDeviceDestroyIOProcID(agg, proc!)
        AudioHardwareDestroyAggregateDevice(agg)
        AudioHardwareDestroyProcessTap(tap)
    }
    signal(SIGTERM, SIG_IGN)                                   // device_watch stops us at the end of a call
    termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    termSource?.setEventHandler { stop(); exit(0) }
    termSource?.resume()

    let started = Date()
    Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { _ in newChunk() }
    Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { t in
        let elapsed = Int(Date().timeIntervalSince(started))
        if postURL == nil {
            let bars = String(repeating: "▮", count: min(20, Int(level * 200)))
            level = 0
            out("  \(elapsed)s  level \(bars.isEmpty ? "·" : bars)  sounding: \(soundingProcesses().joined(separator: ", "))")
        }
        guard elapsed >= seconds else { return }
        t.invalidate()
        stop()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            out("")
            out(peak > 0.002 ? "RESULT: audio received (peak level \(String(format: "%.3f", peak)))"
                             : "RESULT: no audio received. If a call was live, the tap can't hear it (or permission was denied).")
            out(!transcribing ? "RESULT: not transcribed (see the on-device line above)"
                : transcript.isEmpty ? "RESULT: no transcript (no speech heard)"
                                   : "RESULT: transcript → \"\(transcript)\"")
            exit(0)
        }
    }
}

out(postURL == nil ? "ElderShield capture test: listening to system audio for \(seconds)s. Speak on the call now."
                   : "ElderShield listener: sending what it hears to \(postURL!.absoluteString)")
out("  audio processes now: \(soundingProcesses().joined(separator: ", ").ifEmpty("none"))")
SFSpeechRecognizer.requestAuthorization { status in
    DispatchQueue.main.async {
        out(status == .authorized ? "✓ speech recognition allowed"
                                  : "! speech recognition not allowed (\(status.rawValue)); audio check still runs")
        if status == .authorized {
            if recognizer?.supportsOnDeviceRecognition == true {
                out("✓ speech is transcribed on this Mac")
                transcribing = true
            } else if allowCloud {
                out("! the on-device speech model isn't installed; Apple's servers transcribe instead (--allow-cloud)")
                transcribing = true
            } else {
                out("✗ the on-device speech model isn't installed, so nothing will be transcribed. To install it: "
                    + "System Settings → Keyboard → Dictation → turn it on (and pick English), wait a few minutes "
                    + "for the download, then run again. Or pass --allow-cloud to let Apple's servers transcribe.")
            }
            newChunk()
        }
        startCapture()
    }
}
RunLoop.main.run()

extension String { func ifEmpty(_ s: String) -> String { isEmpty ? s : self } }
