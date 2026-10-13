import Foundation

// Synthetic records, never NSRunningApplication instances.
struct Descriptor: Codable {
    let bundleIdentifier: String?
    let pid: Int
}
struct Fixture: Codable {
    let id: String
    let family: String
    let query: String
    let descriptors: [Descriptor]
}
struct Row: Codable {
    let id: String
    let family: String
    let method: String
    let query: String
    let outcome: String
    let capturedPID: Int?
    let trace: [String]
}

// Deliberately independent copy for the proposed policy. Normalize BOTH sides.
let denied = ["com.1password.1password", "com.1password.safari",
              "com.bitwarden.desktop", "com.dashlane.dashlanephonefinal",
              "com.lastpass.LastPass", "com.nordsec.nordpass",
              "me.proton.pass.electron", "me.proton.pass.catalyst"]
let foldedDenied = Set(denied.map { $0.lowercased() })
let fault = CommandLine.arguments.dropFirst().first ?? "none"
precondition(["none", "skip-check", "deny-all"].contains(fault))
let fixtures = try JSONDecoder().decode([Fixture].self, from: FileHandle.standardInput.readDataToEndOfFile())
var rows: [Row] = []
for fixture in fixtures {
    for method in ["original-query-check", "resolved-identity-check"] {
        let query = fixture.query.trimmingCharacters(in: .whitespacesAndNewlines)
        precondition(query.contains("."), "Only bundle-ID branch is in scope")
        var trace: [String] = []
        var outcome = "not-found"
        var captured: Int? = nil
        let rawDenied = AppSafetyPolicy.isBlocked(bundleIdentifier: query)
        // Original order: query membership before lookup. Proposed order:
        // resolve a supplied record, check its ID, then capture that same record.
        if method == "original-query-check" && rawDenied {
            trace.append("query-policy:deny")
            outcome = "denied"
        } else {
            if method == "original-query-check" { trace.append("query-policy:allow") }
            if let record = originalMatch(fixture.descriptors, query) {
                trace.append("resolve:pid=\(record.pid),id=\(record.bundleIdentifier ?? "nil")")
                let identityDenied = record.bundleIdentifier.map { foldedDenied.contains($0.lowercased()) } ?? true
                let stop = method == "resolved-identity-check" &&
                    (fault == "deny-all" || (fault != "skip-check" && identityDenied))
                if method == "resolved-identity-check" { trace.append(stop ? "resolved-policy:deny" : "resolved-policy:allow") }
                if stop {
                    outcome = "denied"
                } else {
                    // The only sink is this in-memory integer capture.
                    captured = record.pid
                    trace.append("capture:pid=\(record.pid)")
                    outcome = "captured"
                }
            } else { trace.append("resolve:none") }
        }
        rows.append(Row(id: fixture.id, family: fixture.family, method: method,
                        query: fixture.query, outcome: outcome, capturedPID: captured, trace: trace))
    }
}
let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
FileHandle.standardOutput.write(try encoder.encode(rows))
