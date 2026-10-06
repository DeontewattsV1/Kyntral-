// SPDX-License-Identifier: BUSL-1.1

import Foundation

public enum KyntralRiskClass: String, Codable, Sendable {
    case k0 = "K0"
    case k1 = "K1"
    case k2 = "K2"
    case k3 = "K3"
    case k4 = "K4"
}

public struct KyntralExecutionResult: Sendable {
    public let completed: Int
    public let failed: Int
}

public protocol KyntralCapability: Sendable {
    var id: String { get }
    var risk: KyntralRiskClass { get }

    func validate() async throws
    func execute() async throws -> KyntralExecutionResult
}
