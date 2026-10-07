// SPDX-License-Identifier: BUSL-1.1

import XCTest
@testable import Kyntral

final class AuthorizationDecisionTests: XCTestCase {
    func testOnlyAllowedPermitsExecution() {
        XCTAssertTrue(AuthorizationDecision.allowed.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.denied.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.unknown.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.expired.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.revoked.permitsExecution)
    }
}
