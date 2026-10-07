// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

final class DedupeLedgerTests: XCTestCase {
    func testURLFragmentAndHostCaseDoNotChangeSourceIdentity() {
        let first = URL(string: "https://EXAMPLE.com/media?id=1#one")!
        let second = URL(string: "https://example.com/media?id=1#two")!

        XCTAssertEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }

    func testDifferentQueryProducesDifferentSourceIdentity() {
        let first = URL(string: "https://example.com/media?id=1")!
        let second = URL(string: "https://example.com/media?id=2")!

        XCTAssertNotEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }
}
