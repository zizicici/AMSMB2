//
//  SMB2TimestampTests.swift
//  AMSMB2
//
//  Distributed under MIT license.
//

import XCTest

@testable import AMSMB2

final class SMB2TimestampTests: XCTestCase, @unchecked Sendable {
    func testConvertsUnixEpochAndFractionalSeconds() throws {
        let epoch = try SMB2Timestamp(Date(timeIntervalSince1970: 0))
        XCTAssertEqual(epoch.seconds, 0)
        XCTAssertEqual(epoch.nanoseconds, 0)

        let fractional = try SMB2Timestamp(Date(timeIntervalSince1970: 1.25))
        XCTAssertEqual(fractional.seconds, 1)
        XCTAssertEqual(fractional.nanoseconds, 250_000_000)
    }

    func testRejectsNegativeNonFiniteAndOverflowingDates() {
        let invalidDates = [
            Date(timeIntervalSince1970: -1),
            Date(timeIntervalSince1970: -0.5),
            Date(timeIntervalSince1970: .nan),
            Date(timeIntervalSince1970: .infinity),
            Date(timeIntervalSince1970: Double(Int64.max)),
            Date(timeIntervalSince1970: .greatestFiniteMagnitude),
        ]

        for date in invalidDates {
            XCTAssertThrowsError(try SMB2Timestamp(date)) { error in
                XCTAssertEqual((error as? POSIXError)?.code, .EINVAL)
            }
        }
    }

    @MainActor
    func testCallbackSetAttributesRejectsEveryUnrepresentableDateKey() {
        let manager = makeManager()
        let keys: [URLResourceKey] = [
            .creationDateKey,
            .contentAccessDateKey,
            .contentModificationDateKey,
            .attributeModificationDateKey,
        ]

        for key in keys {
            let completion = expectation(description: key.rawValue)
            manager.setAttributes(
                attributes: [key: Date(timeIntervalSince1970: -1)],
                ofItemAtPath: "/unused"
            ) { error in
                XCTAssertEqual((error as? POSIXError)?.code, .EINVAL)
                completion.fulfill()
            }
        }

        waitForExpectations(timeout: 1)
    }

    func testAsyncSetAttributesThrowsInsteadOfTrapping() async {
        let manager = makeManager()

        do {
            try await manager.setAttributes(
                attributes: [.contentModificationDateKey: Date(timeIntervalSince1970: -1)],
                ofItemAtPath: "/unused"
            )
            XCTFail("Expected an invalid-argument error")
        } catch {
            XCTAssertEqual((error as? POSIXError)?.code, .EINVAL)
        }
    }

    private func makeManager() -> SMB2Manager {
        SMB2Manager(url: URL(string: "smb://localhost")!, credential: nil)!
    }
}
