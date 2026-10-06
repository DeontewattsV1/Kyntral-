// SPDX-License-Identifier: BUSL-1.1

import Foundation

/// Authorization states are intentionally non-collapsible.
/// Only `allowed` permits execution.
public enum AuthorizationDecision: String, Codable, Sendable {
    case allowed = "Allowed"
    case denied = "Denied"
    case unknown = "Unknown"
    case expired = "Expired"
    case revoked = "Revoked"

    public var permitsExecution: Bool {
        self == .allowed
    }
}
