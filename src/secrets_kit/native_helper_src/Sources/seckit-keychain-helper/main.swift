import Foundation
import SeckitKeychainCore

if CommandLine.arguments.contains("--version") {
    print(helperVersion)
    exit(0)
}

let input = FileHandle.standardInput.readDataToEndOfFile()
guard let raw = String(data: input, encoding: .utf8), !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
    fputs("missing helper request on stdin\n", stderr)
    exit(1)
}

do {
    let decoder = JSONDecoder()
    let request = try decoder.decode(HelperRequest.self, from: Data(raw.utf8))
    let response = try KeychainHelper.process(request)
    let encoder = JSONEncoder()
    let output = try encoder.encode(response)
    FileHandle.standardOutput.write(output)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(0)
} catch let error as HelperError {
    fputs("\(error.description)\n", stderr)
    exit(1)
} catch {
    fputs("\(error)\n", stderr)
    exit(1)
}
