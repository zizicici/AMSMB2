//
//  SMB2WireFormatTests.swift
//  AMSMB2
//
//  Byte-level golden tests for the Swift-side wire encoders, verified
//  against [MS-SMB2]/[MS-FSCC] in the third full review round.
//
//  Distributed under MIT license.
//

import XCTest
@testable import AMSMB2
import SMB2

final class SMB2WireFormatTests: XCTestCase {
    // MARK: lease create context

    func test_leaseContextV1Layout() {
        let key = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
        let context = SMB2FileHandle.CreateLeaseContext(
            state: [.readCaching, .handleCaching], key: key, parentKey: nil
        )
        let blob = Data(context.regions.joined())
        XCTAssertEqual(blob.count, 24 + 32, "V1 context is 56 bytes")

        // Header: Next=0, NameOffset=16, NameLength=4, Reserved=0, DataOffset=24
        XCTAssertEqual(blob.scanValue(offset: 0, as: UInt32.self), 0)
        XCTAssertEqual(blob.scanValue(offset: 4, as: UInt16.self), 16)
        XCTAssertEqual(blob.scanValue(offset: 6, as: UInt16.self), 4)
        XCTAssertEqual(blob.scanValue(offset: 8, as: UInt16.self), 0)
        XCTAssertEqual(blob.scanValue(offset: 10, as: UInt16.self), 24)
        XCTAssertEqual(blob.scanValue(offset: 12, as: UInt32.self), 32, "DataLength: V1 lease is 32")
        // The create context name is network byte order ("RqLs"), the one
        // SMB2 field that is NOT little-endian.
        XCTAssertEqual(Array(blob[16..<20]), [0x52, 0x71, 0x4c, 0x73])
        XCTAssertEqual(blob.scanValue(offset: 44, as: UInt32.self), 0, "V1 LeaseFlags must be 0")
        XCTAssertEqual(blob[24..<40], Data(value: key))
        XCTAssertEqual(blob.scanValue(offset: 40, as: UInt32.self), 0x3, "read+handle caching state")
    }

    func test_leaseContextV2LayoutWithParent() {
        let key = UUID(uuid: (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
        let parent = UUID(uuid: (16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1))
        let context = SMB2FileHandle.CreateLeaseContext(
            state: [.readCaching], key: key, parentKey: parent
        )
        let blob = Data(context.regions.joined())
        XCTAssertEqual(blob.count, 24 + 52, "V2 context is 76 bytes")
        XCTAssertEqual(blob.scanValue(offset: 12, as: UInt32.self), 52, "DataLength: V2 lease is 52")
        XCTAssertEqual(Array(blob[16..<20]), [0x52, 0x71, 0x4c, 0x73])
        XCTAssertEqual(
            blob.scanValue(offset: 44, as: UInt32.self), 0x4,
            "V2 with a parent key must set SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET"
        )
        XCTAssertEqual(blob[56..<72], Data(value: parent), "parent key follows the V1 fields")
    }

    // MARK: symbolic link reparse buffer

    func test_symbolicLinkReparseDataLength() throws {
        let reparse = IOCtl.SymbolicLinkReparse(path: "target\\file.txt", isRelative: true)
        let blob = Data(reparse.regions.joined())
        let substitute = "target\\file.txt".data(using: .utf16LittleEndian)!
        let print = "target\\file.txt".data(using: .utf16LittleEndian)!

        XCTAssertEqual(
            blob.scanValue(offset: 4, as: UInt16.self),
            UInt16(12 + substitute.count + print.count),
            "ReparseDataLength = 12 + PathBuffer, not the bare buffer size"
        )
        XCTAssertEqual(blob.scanValue(offset: 16, as: UInt32.self), 1, "relative flag")
        XCTAssertEqual(blob.count, 20 + substitute.count + print.count, "8-byte reparse header + 12 bytes of fields + buffer")

        // The encoder must satisfy its own decoder (the old length made this
        // roundtrip impossible) and tolerate server padding on decode.
        let roundtrip = try IOCtl.SymbolicLinkReparse(data: blob)
        XCTAssertEqual(roundtrip.substituteName, "target\\file.txt")
        XCTAssertEqual(roundtrip.isRelative, true)
        let padded = blob + Data(repeating: 0, count: 8)
        XCTAssertEqual(try IOCtl.SymbolicLinkReparse(data: padded).substituteName, "target\\file.txt")
    }

    // MARK: int64Range must not trap on whole-file range expressions

    func test_int64RangeHandlesMaxBounds() {
        XCTAssertEqual((0...Int64.max).int64Range, 0..<Int64.max)
        XCTAssertEqual((...Int64.max).int64Range, 0..<Int64.max)
        XCTAssertEqual((0...UInt64.max).int64Range, 0..<Int64.max)
        XCTAssertEqual((...UInt64.max).int64Range, 0..<Int64.max)
        XCTAssertEqual((Int64.max...Int64.max).int64Range.lowerBound, Int64.max)
        XCTAssertEqual((10...20).int64Range, 10..<21)
        XCTAssertEqual((..<10).int64Range, 0..<10)
        XCTAssertEqual((5..<Int32.max).int64Range, 5..<Int64(Int32.max))
        XCTAssertEqual((100...).int64Range, 100..<Int64.max)
        XCTAssertEqual((0..<0).int64Range, 0..<0)
        // Narrow bounds whose successor is representable must NOT be
        // widened to "the whole file".
        XCTAssertEqual((0...UInt32.max).int64Range, 0..<4_294_967_296)
        XCTAssertEqual((0...Int8.max).int64Range, 0..<128)
        XCTAssertEqual((...UInt16.max).int64Range, 0..<65_536)
        // Negative lower bounds clamp to 0 (file offsets are non-negative),
        // which also keeps upper - lower from overflowing downstream.
        XCTAssertEqual((Int64(-5)..<10).int64Range, 0..<10)
        XCTAssertEqual((Int64.min...Int64(-1)).int64Range, 0..<0)
        XCTAssertEqual((Int8(-5)...).int64Range, 0..<Int64.max)
    }

    // MARK: reparse decoders reject names that live in the padding

    func test_reparseDecodersRejectNamesOutsideDeclaredData() throws {
        // Declared data ends at offset 20 (count 12), but the substitute name
        // claims 20 bytes starting at 8: it would be read from the padding.
        var blob = Data()
        blob.append(value: UInt32(SMB2_REPARSE_TAG_SYMLINK))
        blob.append(value: 12 as UInt16) // ReparseDataLength
        blob.append(value: 0 as UInt16)
        blob.append(value: 8 as UInt16) // substitute offset
        blob.append(value: 20 as UInt16) // substitute length (overruns count)
        blob.append(value: 0 as UInt16)
        blob.append(value: 0 as UInt16)
        blob.append(value: 0 as UInt32)
        blob.append(Data(repeating: 0x41, count: 40)) // padding
        XCTAssertThrowsError(try IOCtl.SymbolicLinkReparse(data: blob))
    }

    // MARK: overallSize saturates instead of trapping

    func test_overallSizeSaturates() {
        let huge = NSNumber(value: Int64(5_000_000_000_000_000_000))
        let entry: [URLResourceKey: any Sendable] = [
            .isRegularFileKey: NSNumber(value: true), .fileSizeKey: huge,
        ]
        // Two "legal" sizes whose sum exceeds Int64.max used to trap.
        XCTAssertEqual([entry, entry].overallSize, Int64.max)
    }
}
