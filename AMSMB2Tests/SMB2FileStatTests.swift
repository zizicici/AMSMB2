//
//  SMB2FileStatTests.swift
//  AMSMB2
//
//  Distributed under MIT license.
//

import XCTest
import SMB2
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import AMSMB2

final class SMB2FileStatTests: XCTestCase {
    func testFileInfoPreservesMetadataAndPre1970Timestamps() {
        var info = smb2_file_all_info()
        info.basic.file_attributes = UInt32(SMB2_FILE_ATTRIBUTE_ARCHIVE)
        info.standard.end_of_file = 5_000_000_000
        info.standard.number_of_links = 3
        info.index_number = 42
        info.basic.last_access_time = smb2_timeval(tv_sec: -1, tv_usec: 125_000)
        info.basic.last_write_time = smb2_timeval(tv_sec: -315_619_200, tv_usec: 250_000)
        info.basic.change_time = smb2_timeval(tv_sec: 12, tv_usec: 500_000)
        info.basic.creation_time = smb2_timeval(tv_sec: -1_420_156_800, tv_usec: 750_000)

        let stat = smb2_stat_64(fileInfo: info)
        XCTAssertEqual(stat.resourceType, .file)
        XCTAssertEqual(stat.smb2_attributes, info.basic.file_attributes)
        XCTAssertEqual(stat.smb2_size, 5_000_000_000)
        XCTAssertEqual(stat.smb2_nlink, 3)
        XCTAssertEqual(stat.smb2_ino, 42)

        var values: [URLResourceKey: any Sendable] = [:]
        stat.populateResourceValue(&values)
        let expected: [(URLResourceKey, TimeInterval)] = [
            (.contentAccessDateKey, -0.875),
            (.contentModificationDateKey, -315_619_199.75),
            (.attributeModificationDateKey, 12.5),
            (.creationDateKey, -1_420_156_799.25),
        ]
        for (key, seconds) in expected {
            XCTAssertEqual((values[key] as? Date)?.timeIntervalSince1970 ?? .nan, seconds, accuracy: 0.000_001)
        }
    }

    func testNonReparseFilesIgnoreTagsAndKeepDirectoryType() {
        var info = smb2_file_all_info()
        info.basic.file_attributes = UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        var stat = smb2_stat_64(fileInfo: info)
        stat.setResourceType(reparseTag: UInt32(SMB2_REPARSE_TAG_SYMLINK))
        XCTAssertEqual(stat.resourceType, .directory)
        XCTAssertEqual(stat.smb2_reparse_tag, 0)
    }

    func testReparsePointsPreserveLinkAndSpecialFileTypes() {
        var info = smb2_file_all_info()
        info.basic.file_attributes = UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT)
        var stat = smb2_stat_64(fileInfo: info)
        // No tag (including a server that rejects the query) keeps the legacy link fallback.
        XCTAssertEqual(stat.resourceType, .link)

        let cases: [(UInt32, UInt32)] = [
            (UInt32(SMB2_REPARSE_TAG_SYMLINK), UInt32(SMB2_TYPE_LINK)),
            (UInt32(SMB2_REPARSE_TAG_MOUNT_POINT), UInt32(SMB2_TYPE_LINK)),
            (UInt32(SMB2_REPARSE_TAG_LX_SYMLINK), UInt32(SMB2_TYPE_LINK)),
            (UInt32(SMB2_REPARSE_TAG_LX_FIFO), UInt32(SMB2_TYPE_FIFO)),
            (UInt32(SMB2_REPARSE_TAG_LX_CHR), UInt32(SMB2_TYPE_CHARDEV)),
            (UInt32(SMB2_REPARSE_TAG_LX_BLK), UInt32(SMB2_TYPE_BLOCKDEV)),
            (UInt32(SMB2_REPARSE_TAG_AF_UNIX), UInt32(SMB2_TYPE_SOCKET)),
            (0xA000_FFFE, UInt32(SMB2_TYPE_LINK)), // Unknown name-surrogate tag.
            (0x8000_FFFE, UInt32(SMB2_TYPE_FILE)), // Unknown ordinary reparse tag.
        ]
        for (tag, type) in cases {
            stat.setResourceType(reparseTag: tag)
            XCTAssertEqual(stat.smb2_type, type, "Reparse tag: \(String(tag, radix: 16))")
            XCTAssertEqual(stat.smb2_reparse_tag, tag)
        }
        stat.smb2_attributes |= UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY)
        stat.setResourceType(reparseTag: 0x8000_FFFE)
        XCTAssertEqual(stat.resourceType, .directory)
    }

    func testFstatCompoundClassifiesInOrder() throws {
        try withStatPeer(replies: [tagReply(), .all(attributes: UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT))]) { file in
            let stat = try file.fstat()
            XCTAssertEqual(stat.resourceType, .link)
            XCTAssertEqual(stat.smb2_reparse_tag, UInt32(SMB2_REPARSE_TAG_SYMLINK))
            XCTAssertEqual(stat.smb2_size, 5_000_000_000)
            XCTAssertEqual(stat.smb2_ino, 42)
        }
    }

    func testFstatCompoundAppliesLateTagWhenInfoRepliesFirst() throws {
        // The fstat compound is unrelated, so the server may reorder the
        // replies: the info reply first, the attribute tag late. The tag
        // must still be applied at completion.
        try withStatPeer(
            replies: [tagReply(), .all(attributes: UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT))],
            reverseReplyOrder: true
        ) { file in
            let stat = try file.fstat()
            XCTAssertEqual(stat.resourceType, .link)
            XCTAssertEqual(stat.smb2_reparse_tag, UInt32(SMB2_REPARSE_TAG_SYMLINK))
        }
    }

    func testFstatFallsBackWhenTagQueryIsUnsupported() throws {
        try withStatPeer(replies: [
            StatReply(infoClass: UInt8(SMB2_FILE_ATTRIBUTE_TAG_INFORMATION),
                      status: UInt32(SMB2_STATUS_INVALID_INFO_CLASS)),
            .all(attributes: UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT)),
        ]) { file in
            let stat = try file.fstat()
            XCTAssertEqual(stat.resourceType, .link)
            XCTAssertEqual(stat.smb2_reparse_tag, 0)
            XCTAssertEqual(stat.smb2_size, 5_000_000_000)
        }
    }

    func testFstatRegularFileIgnoresTag() throws {
        try withStatPeer(replies: [
            tagReply(),
            .all(attributes: UInt32(SMB2_FILE_ATTRIBUTE_ARCHIVE)),
        ]) { file in
            let stat = try file.fstat()
            XCTAssertEqual(stat.resourceType, .file)
            XCTAssertEqual(stat.smb2_reparse_tag, 0)
        }
    }

    func testFstatRejectsEmptyFileInfoReply() throws {
        try withStatPeer(replies: [
            tagReply(),
            StatReply(infoClass: UInt8(SMB2_FILE_ALL_INFORMATION)),
        ]) { file in
            XCTAssertThrowsError(try file.fstat()) { error in
                XCTAssertEqual((error as? POSIXError)?.code, .EIO)
            }
        }
    }

    func testFstatTagTimeoutFallsBack() throws {
        // The tag query is optional in the compound: when it never gets a
        // reply, its PDU timeout completes it and fstat still succeeds with
        // the tag-less fallback (the connection is torn down by the timeout).
        try withStatPeer(
            replies: [nil, .all(attributes: UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT))],
            expectsClose: false
        ) { file in
            let stat = try file.fstat()
            XCTAssertEqual(stat.resourceType, .link)
            XCTAssertEqual(stat.smb2_reparse_tag, 0)
        }
    }

    private func tagReply() -> StatReply {
        var tag = Data(repeating: 0, count: 8)
        tag.put(UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT), at: 0)
        tag.put(UInt32(SMB2_REPARSE_TAG_SYMLINK), at: 4)
        return StatReply(infoClass: UInt8(SMB2_FILE_ATTRIBUTE_TAG_INFORMATION), output: tag)
    }

    /// Speaks the fstat compound: one chained request packet carrying the
    /// attribute-tag and all-info queries, answered per member (optionally in
    /// reverse order), then a CLOSE unless the caller expects the teardown
    /// path. `replies` are in chain order; nil never answers that member.
    private func withStatPeer(
        replies: [StatReply?],
        reverseReplyOrder: Bool = false,
        expectsClose: Bool = true,
        check: (SMB2FileHandle) throws -> Void
    ) throws {
        var sockets: [Int32] = [-1, -1]
#if canImport(Darwin)
        let socketType = SOCK_STREAM
#else
        let socketType = Int32(SOCK_STREAM.rawValue)
#endif
        XCTAssertEqual(socketpair(AF_UNIX, socketType, 0, &sockets), 0)
        guard sockets[0] >= 0 else { throw POSIXError(.EIO) }
        XCTAssertEqual(fcntl(sockets[0], F_SETFL, O_NONBLOCK), 0)
        let peerFD = sockets[1]
        var deadline = timeval(tv_sec: 8, tv_usec: 0)
        _ = setsockopt(peerFD, SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
#if canImport(Darwin)
        var noSignal: Int32 = 1
        _ = setsockopt(peerFD, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
#endif
        let finished = expectation(description: "SMB query peer completed")
        DispatchQueue.global().async {
            defer {
                _ = close(peerFD)
                finished.fulfill()
            }
            do {
                let packet = try receivePacket(peerFD)
                var members = [Data]()
                var slice = packet
                while true {
                    members.append(slice)
                    let next = slice.integer(at: 20, as: UInt32.self)
                    if next == 0 || next >= slice.count { break }
                    slice = slice.subdata(in: Int(next)..<slice.count)
                }
                XCTAssertEqual(members.count, 2, "fstat sends one compound with two queries")
                XCTAssertEqual(members[0].integer(at: 12, as: UInt16.self), UInt16(SMB2_QUERY_INFO.rawValue))
                XCTAssertEqual(members[1].integer(at: 12, as: UInt16.self), UInt16(SMB2_QUERY_INFO.rawValue))
                XCTAssertGreaterThan(members[0].integer(at: 20, as: UInt32.self), 0, "chained via NextCommand")
                XCTAssertEqual(members[1].integer(at: 20, as: UInt32.self), 0)
                XCTAssertEqual(members[0][67], UInt8(SMB2_FILE_ATTRIBUTE_TAG_INFORMATION))
                XCTAssertEqual(members[1][67], UInt8(SMB2_FILE_ALL_INFORMATION))

                var order = [Int](replies.indices)
                if reverseReplyOrder { order.reverse() }
                for index in order {
                    guard let reply = replies[index] else { continue }
                    try sendPacket(peerFD, reply.packet(for: members[index]))
                }

                if expectsClose {
                    let request = try receivePacket(peerFD)
                    XCTAssertEqual(request.integer(at: 12, as: UInt16.self), UInt16(SMB2_CLOSE.rawValue))
                    var body = Data(repeating: 0, count: 60)
                    body.put(UInt16(60), at: 0)
                    try sendPacket(peerFD, responseHeader(for: request) + body)
                } else {
                    var byte: UInt8 = 0
                    XCTAssertEqual(recv(peerFD, &byte, 1, 0), 0, "client must tear the connection down")
                }
            } catch {
                XCTFail("SMB query peer failed: \(error)")
            }
        }

        let client = try SMB2Client()
        try client.withThreadSafeContext { context in
            context.pointee.fd = sockets[0]
            context.pointee.credits = 32
            context.pointee.dialect = UInt16(SMB2_VERSION_0302.rawValue)
            context.pointee.max_transact_size = 65_536
        }
        client.timeout = 2
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        defer {
            try? file.close()
            client.destroyContext()
            wait(for: [finished], timeout: 8)
        }
        try check(file)
    }
}

private struct StatReply: Sendable {
    let infoClass: UInt8
    var status: UInt32 = 0
    var output = Data()

    static func all(attributes: UInt32) -> Self {
        var output = Data(repeating: 0, count: 100)
        for offset in stride(from: 0, to: 32, by: 8) {
            output.put(UInt64(116_444_736_000_000_000), at: offset)
        }
        output.put(attributes, at: 32)
        output.put(UInt64(5_000_000_000), at: 48)
        output.put(UInt32(3), at: 56)
        output.put(UInt64(42), at: 64)
        return Self(infoClass: UInt8(SMB2_FILE_ALL_INFORMATION), output: output)
    }

    func packet(for request: Data) -> Data {
        var body = Data(repeating: 0, count: 8)
        body.put(UInt16(9), at: 0)
        if status == 0 {
            body.put(UInt16(72), at: 2)
            body.put(UInt32(output.count), at: 4)
            body.append(output)
        }
        return responseHeader(for: request, status: status) + body
    }
}

private func responseHeader(for request: Data, status: UInt32 = 0) -> Data {
    var header = Data(request.prefix(64))
    header.put(status, at: 8)
    header.put(UInt16(1), at: 14) // Grant a credit for the next request.
    header.put(UInt32(SMB2_FLAGS_SERVER_TO_REDIR), at: 16)
    header.put(UInt32(0), at: 20)
    return header
}

private func receivePacket(_ fd: Int32) throws -> Data {
    func receive(_ count: Int) throws -> Data {
        var data = Data(repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let received = data.withUnsafeMutableBytes { bytes in
                recv(fd, bytes.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            guard received > 0 else { throw POSIXError(.EIO) }
            offset += received
        }
        return data
    }
    let prefix = try receive(4)
    let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
    guard length >= 64, length <= 8 << 20 else { throw POSIXError(.EIO) }
    return try receive(length)
}

private func sendPacket(_ fd: Int32, _ packet: Data) throws {
    var prefix = UInt32(packet.count).bigEndian
    let data = withUnsafeBytes(of: &prefix) { Data($0) } + packet
    var offset = 0
    while offset < data.count {
        let sent = data.withUnsafeBytes { bytes in
#if canImport(Darwin)
            send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
#else
            send(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, Int32(MSG_NOSIGNAL))
#endif
        }
        guard sent > 0 else { throw POSIXError(.EIO) }
        offset += sent
    }
}

private extension Data {
    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { bytes in
            replaceSubrange(offset..<(offset + bytes.count), with: bytes)
        }
    }

    func integer<T: FixedWidthInteger>(at offset: Int, as type: T.Type) -> T {
        withUnsafeBytes { T(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: type)) }
    }
}
