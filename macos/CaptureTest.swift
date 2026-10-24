// ElderShield capture test: can a third-party program hear a FaceTime call on this Mac?
//
// Taps all system audio (everything except this program) with a Core Audio process tap
// (macOS 14.2+), shows a level meter and which processes are producing sound, and runs
// Apple's on-device speech recognizer on what it hears. Nothing is saved.
//
//   macos/capture-test.sh [--seconds 20]     (run it during a FaceTime call)
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
let seconds = Int(arg("--seconds") ?? "") ?? 20
// Launched with `open` (so macOS attributes the permission prompts to this app, not the
// terminal), stdout goes nowhere; the script tails this file instead.
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
    return AudioObjectGetPropertyData(obj, &addr, 0, nil, &size, &value)
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
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let name = (out.trimmingCharacters(in: .whitespacesAndNewlines) as NSString).lastPathComponent
    nameCache[pid] = name.isEmpty ? "pid \(pid)" : name
    return nameCache[pid]!
}

/// Processes currently producing audio output, by name.
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

// --- speech ---------------------------------------------------------------------------
var transcript = ""
var request: SFSpeechAudioBufferRecognitionRequest?

func startSpeech() {
    guard let recognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US")) else {
        out("✗ speech recognizer unavailable"); return
    }
    let req = SFSpeechAudioBufferRecognitionRequest()
    req.shouldReportPartialResults = true
    if recognizer.supportsOnDeviceRecognition {
        req.requiresOnDeviceRecognition = true
        out("✓ on-device speech recognition available")
    } else {
        out("! on-device recognition not available for en-US on this Mac; this test uses Apple's server instead")
    }
    request = req
    recognizer.recognitionTask(with: req) { result, error in
        // The recognizer sends an empty final result after the audio ends; keep the words.
        if let r = result, !r.bestTranscription.formattedString.isEmpty,
           r.bestTranscription.formattedString != transcript {
            transcript = r.bestTranscription.formattedString
            out("  transcript: \(transcript)")
        }
        if let e = error as NSError?, e.code != 216, e.code != 1110 {   // 216/1110: cancelled / no speech
            out("  speech: \(e.localizedDescription)")
        }
    }
}

// --- capture --------------------------------------------------------------------------
var peak: Float = 0
var lastLevelPrint = Date()

func startCapture() {
    let desc = CATapDescription(stereoGlobalTapButExcludeProcesses: [])
    desc.name = "ElderShield capture test"
    desc.isPrivate = true
    desc.muteBehavior = .unmuted
    var tap = AudioObjectID(kAudioObjectUnknown)
    check(AudioHardwareCreateProcessTap(desc, &tap), "create system audio tap")

    var outDevice = AudioObjectID(kAudioObjectUnknown)
    check(get(AudioObjectID(kAudioObjectSystemObject), kAudioHardwarePropertyDefaultOutputDevice, &outDevice), "default output")
    var outUID: CFString = "" as CFString
    check(get(outDevice, kAudioDevicePropertyDeviceUID, &outUID), "output UID")

    let aggDesc: [String: Any] = [
        kAudioAggregateDeviceNameKey: "ElderShield capture test",
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
        request?.append(buf)
    }, "create IO proc")
    check(AudioDeviceStart(agg, proc), "start capture")

    let started = Date()
    Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { t in
        let elapsed = Int(Date().timeIntervalSince(started))
        let bars = String(repeating: "▮", count: min(20, Int(peak * 200)))
        out("  \(elapsed)s  level \(bars.isEmpty ? "·" : bars)  sounding: \(soundingProcesses().joined(separator: ", "))")
        if elapsed >= seconds {
            t.invalidate()
            request?.endAudio()
            AudioDeviceStop(agg, proc)
            AudioDeviceDestroyIOProcID(agg, proc!)
            AudioHardwareDestroyAggregateDevice(agg)
            AudioHardwareDestroyProcessTap(tap)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                out("")
                out(peak > 0.002 ? "RESULT: audio received (peak level \(String(format: "%.3f", peak)))"
                                   : "RESULT: no audio received. If a call was live, the tap can't hear it (or permission was denied).")
                out(transcript.isEmpty ? "RESULT: no transcript (no speech heard, or recognition unavailable)"
                                         : "RESULT: transcript → \"\(transcript)\"")
                exit(0)
            }
        }
    }
}

out("ElderShield capture test: listening to system audio for \(seconds)s. Speak on the call now.")
out("  audio processes now: \(soundingProcesses().joined(separator: ", ").ifEmpty("none"))")
SFSpeechRecognizer.requestAuthorization { status in
    DispatchQueue.main.async {
        out(status == .authorized ? "✓ speech recognition allowed"
                                    : "! speech recognition not allowed (\(status.rawValue)); audio check still runs")
        if status == .authorized { startSpeech() }
        startCapture()
    }
}
RunLoop.main.run()

extension String { func ifEmpty(_ s: String) -> String { isEmpty ? s : self } }
