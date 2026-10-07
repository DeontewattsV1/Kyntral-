// SPDX-License-Identifier: BUSL-1.1

import Foundation

public indirect enum KCJValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case string(String)
    case integer(Int64)
    case array([KCJValue])
    case object([String: KCJValue])
}

public enum KCJError: Error {
    case duplicateNormalizedKey
}

public enum KCJCanonicalizer {
    public static func data(_ value: KCJValue) throws -> Data {
        Data(try string(value).utf8)
    }

    public static func string(_ value: KCJValue) throws -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .integer(let value):
            return String(value)
        case .string(let value):
            return quote(value.precomposedStringWithCanonicalMapping)
        case .array(let values):
            let encoded = try values.map(string).joined(separator: ",")
            return "[" + encoded + "]"
        case .object(let object):
            var normalized: [String: KCJValue] = [:]
            for (key, value) in object {
                let nfc = key.precomposedStringWithCanonicalMapping
                guard normalized[nfc] == nil else {
                    throw KCJError.duplicateNormalizedKey
                }
                normalized[nfc] = value
            }
            let keys = normalized.keys.sorted { lhs, rhs in
                Array(lhs.utf8).lexicographicallyPrecedes(Array(rhs.utf8))
            }
            let fields = try keys.map { key in
                quote(key) + ":" + (try string(normalized[key]!))
            }
            return "{" + fields.joined(separator: ",") + "}"
        }
    }

    public static func signingPreimage(
        purpose: String,
        payload: KCJValue
    ) throws -> Data {
        var data = Data("KYNTRAL\0\(purpose)\0v1\0".utf8)
        data.append(try self.data(payload))
        return data
    }

    private static func quote(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x08: result += "\\b"
            case 0x0C: result += "\\f"
            case 0x0A: result += "\\n"
            case 0x0D: result += "\\r"
            case 0x09: result += "\\t"
            case 0x00...0x1F:
                result += String(format: "\\u%04x", scalar.value)
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        result += "\""
        return result
    }
}
