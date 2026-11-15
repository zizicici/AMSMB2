//
//  SMB2LifetimeTests.swift
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
import FoundationNetworking
#endif
@testable import AMSMB2

final class SMB2LifetimeTests: XCTestCase {
    func testPartialReadTimeoutAbortsBeforeLateBodyAndClose() throws {
        try checkPartialReadTimeout(absoluteOffset: nil)
    }

    func testPartialPreadTimeoutAbortsBeforeLateBodyAndClose() throws {
        try checkPartialReadTimeout(absoluteOffset: 123)
    }

    private func checkPartialReadTimeout(absoluteOffset: UInt64?) throws {
        let (client, peer) = try makeClient()
        let resumeBody = DispatchSemaphore(value: 0)
        let finished = expectation(description: "Late READ peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                let request = try receivePacket(peer)
                XCTAssertEqual(request.number(at: 12, UInt16.self), UInt16(SMB2_READ.rawValue))
                let count = Int(request.number(at: 68, UInt32.self))
                var body = Data(repeating: 0, count: 16)
                body.put(UInt16(17), at: 0)
                body[2] = 80
                body.put(UInt32(count), at: 4)
                let header = response(for: request) + body
                var length = UInt32(header.count + count).bigEndian
                try sendAll(peer, withUnsafeBytes(of: &length) { Data($0) } + header)
                // The READ has left waitqueue and is now the active receive PDU.
                guard resumeBody.wait(timeout: .now() + 10) == .success else {
                    return XCTFail("Timed out waiting to send the late body")
                }
                // A closed connection may reject this write; either way it must
                // never reach the Swift buffer that has just left scope.
                try? sendAll(peer, Data(repeating: 0x41, count: count))
                var byte: UInt8 = 0
                XCTAssertEqual(recv(peer, &byte, 1, 0), 0, "Client must close the timed out connection")
            } catch {
                XCTFail("READ peer: \(error)")
            }
        }
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        defer {
            resumeBody.signal()
            try? file.close()
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        XCTAssertThrowsError(try {
            if let absoluteOffset {
                return try file.read(toAbsoluteOffset: absoluteOffset, length: 8_192)
            }
            return try file.read(length: 8_192)
        }()) { error in
            XCTAssertEqual((error as? POSIXError)?.code, .ETIMEDOUT)
        }
        XCTAssertFalse(client.isActive)
        XCTAssertThrowsError(try client.withThreadSafeContext { _ in })
        resumeBody.signal()
        // This used to service the late body into freed Data storage under ASan.
        try file.close()
    }

    func testRawPDUTimeoutDetachesDecoderAndAbortsContext() throws {
        try checkRawPDUTimeout(partialReply: false)
    }

    func testPartialRawPDUTimeoutDetachesDecoderAndAbortsContext() throws {
        try checkRawPDUTimeout(partialReply: true)
    }

    private func checkRawPDUTimeout(partialReply: Bool) throws {
        let (client, peer) = try makeClient()
        let finished = expectation(description: "Silent query peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                let request = try receivePacket(peer)
                XCTAssertEqual(request.number(at: 12, UInt16.self), UInt16(SMB2_QUERY_INFO.rawValue))
                if partialReply {
                    var body = Data(repeating: 0, count: 8)
                    body.put(UInt16(9), at: 0)
                    body.put(UInt16(72), at: 2)
                    body.put(UInt32(100), at: 4)
                    let header = response(for: request) + body
                    var length = UInt32(header.count + 100).bigEndian
                    try sendAll(peer, withUnsafeBytes(of: &length) { Data($0) } + header)
                }
                var byte: UInt8 = 0
                XCTAssertEqual(recv(peer, &byte, 1, 0), 0)
            } catch {
                XCTFail("Query peer: \(error)")
            }
        }
        defer { client.destroyContext(); wait(for: [finished], timeout: 10) }
        XCTAssertThrowsError(try client.async_await_pdu(dataHandler: { _, _ in
            XCTFail("A timed out query must not invoke its decoder")
        }) { context, callback in
            var request = smb2_query_info_request()
            request.info_type = UInt8(SMB2_0_INFO_FILE)
            request.file_info_class = UInt8(SMB2_FILE_ALL_INFORMATION)
            request.output_buffer_length = 1_024
            return smb2_cmd_query_info_async(context, &request, SMB2Client.generic_handler, callback)
        }) { error in
            XCTAssertEqual((error as? POSIXError)?.code, .ETIMEDOUT)
        }
        XCTAssertFalse(client.isActive)
        XCTAssertThrowsError(try client.withThreadSafeContext { _ in })
    }

    func testStatCompoundPartialReplyTimeoutAbortsAllMembersCleanly() throws {
        try checkCompoundPartialReplyTimeout(
            description: "Partial stat peer finished",
            command: SMB2_CREATE
        ) { client in
            try client.stat("file")
        }
    }

    func testRenameCompoundPartialReplyTimeoutAbortsAllMembersCleanly() throws {
        try checkCompoundPartialReplyTimeout(
            description: "Partial rename peer finished",
            command: SMB2_CREATE
        ) { client in
            try client.rename("old", to: "new")
        }
    }

    func testTruncateCompoundPartialReplyTimeoutAbortsAllMembersCleanly() throws {
        try checkCompoundPartialReplyTimeout(
            description: "Partial truncate peer finished",
            command: SMB2_CREATE
        ) { client in
            try client.resize("file", to: 1_024)
        }
    }

    func testReadlinkCompoundPartialReplyTimeoutAbortsAllMembersCleanly() throws {
        try checkCompoundPartialReplyTimeout(
            description: "Partial readlink peer finished",
            command: SMB2_CREATE
        ) { client in
            try client.readlink("link")
        }
    }

    /// stat/rename/truncate/readlink are all CREATE-led compounds sharing one
    /// C-side callback state between their members. A half-received CREATE
    /// reply leaves the later members queued.
    ///
    /// Completion mechanism (measured): the user-visible ETIMEDOUT comes from
    /// the Swift `timeout + 2` backstop, which tears the context down; the
    /// C-side member accounting (pending refcounting, SHUTDOWN fan-out) runs
    /// during that teardown — so these cases lock the teardown path end to
    /// end, with the ASan run as the memory-safety gate. A pure C-side
    /// timeout completion (without the backstop) is not exercised here.
    private func checkCompoundPartialReplyTimeout(
        description: String,
        command: smb2_command,
        operation: @escaping (SMB2Client) throws -> Void
    ) throws {
        let (client, peer) = try makeClient()
        let finished = expectation(description: description)
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                let request = try receivePacket(peer)
                XCTAssertEqual(request.number(at: 12, UInt16.self), UInt16(command.rawValue))
                var body = Data(repeating: 0, count: 8)
                body.put(UInt16(89), at: 0) // create reply structure size
                body[2] = 0 // oplock level
                body.put(UInt32(1), at: 4) // FILE_OPENED
                // None of the body fields are ever parsed: the fixed section
                // needs 88 bytes and only 8 arrive, so the reply stalls in
                // SMB2_RECV_FIXED and the CREATE PDU becomes smb2->pdu.
                let header = response(for: request) + body
                var length = UInt32(header.count + 100).bigEndian
                try sendAll(peer, withUnsafeBytes(of: &length) { Data($0) } + header)
                // Stall: the CREATE reply never completes. The remaining
                // compound members must be timed out and the context torn down
                // without firing any callback into freed compound state.
                var byte: UInt8 = 0
                XCTAssertEqual(recv(peer, &byte, 1, 0), 0, "Client must close the timed out connection")
            } catch {
                XCTFail("Compound peer: \(error)")
            }
        }
        defer {
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        XCTAssertThrowsError(try operation(client)) { error in
            XCTAssertEqual((error as? POSIXError)?.code, .ETIMEDOUT)
        }
        XCTAssertFalse(client.isActive)
        XCTAssertThrowsError(try client.withThreadSafeContext { _ in })
    }

    func testContextGettersAndSettersDuringConnectionFailure() throws {
        for _ in 0..<12 {
            let (client, peer) = try makeClient()
            try client.withThreadSafeContext { context in
                context.pointee.server = UnsafePointer(strdup("server"))
                context.pointee.share = UnsafePointer(strdup("share"))
            }
            let operations = DispatchGroup()
            operations.enter()
            DispatchQueue.global().async {
                defer { operations.leave() }
                try? client.echo()
            }
            operations.enter()
            DispatchQueue.global().async {
                defer { _ = close(peer); operations.leave() }
                _ = try? receivePacket(peer)
            }
            DispatchQueue.concurrentPerform(iterations: 6) { worker in
                for iteration in 0..<500 {
                    if worker.isMultiple(of: 2) {
                        client.user = "user-\(iteration)"
                        client.domain = "domain-\(iteration)"
                        client.workstation = "host-\(iteration)"
                        client.password = "password-\(iteration)"
                        client.passthrough = false
                    } else {
                        _ = client.user
                        _ = client.domain
                        _ = client.workstation
                        _ = client.password
                        _ = client.server
                        _ = client.share
                        _ = client.timeout
                        _ = client.securityMode
                        _ = client.authentication
                        _ = client.clientGuid
                        _ = client.seal
                        _ = client.passthrough
                        _ = client.opaque
                        _ = client.version
                        _ = client.errorString
                        _ = client.ntError
                        _ = client.maximumTransactionSize
                        _ = client.customMirror
                    }
                }
            }
            XCTAssertEqual(operations.wait(timeout: .now() + 10), .success)
            XCTAssertThrowsError(try client.withThreadSafeContext { _ in })
        }
    }

    func testConcurrentPublicConnectDisconnectEchoAndDebugDescription() throws {
        // Accept then close locally so every connect fails without external services.
        let reserved = socket(AF_INET, streamSocket, 0)
        guard reserved >= 0 else { throw POSIXError(.EIO) }
        defer { _ = close(reserved) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let addressSize = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
#if canImport(Darwin)
                Darwin.bind(reserved, $0, addressSize)
#else
                Glibc.bind(reserved, $0, addressSize)
#endif
            }
        }
        XCTAssertEqual(bound, 0)
        var size = addressSize
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(reserved, $0, &size) }
        }
        XCTAssertEqual(named, 0)
        XCTAssertEqual(listen(reserved, 128), 0)
        let peerFinished = expectation(description: "Failing connect peer finished")
        DispatchQueue.global().async {
            defer { peerFinished.fulfill() }
            for _ in 0..<100 {
                var event = pollfd(fd: reserved, events: Int16(POLLIN), revents: 0)
                guard poll(&event, 1, 10_000) > 0 else {
                    return XCTFail("Timed out accepting the next test connection")
                }
                let peer = accept(reserved, nil, nil)
                guard peer >= 0 else { return XCTFail("Could not accept test connection") }
                _ = close(peer)
            }
        }
        let port = UInt16(bigEndian: address.sin_port)
        let manager = try XCTUnwrap(SMB2Manager(url: URL(string: "smb://127.0.0.1:\(port)")!, credential: nil))
        manager.timeout = 1
        let done = DispatchGroup()
        for _ in 0..<100 {
            done.enter()
            manager.connectShare(name: "unavailable") { _ in done.leave() }
            done.enter()
            manager.disconnectShare(gracefully: false) { _ in done.leave() }
            done.enter()
            manager.echo { _ in done.leave() }
        }
        DispatchQueue.concurrentPerform(iterations: 6) { worker in
            for _ in 0..<1_000 {
                if worker == 0 { manager.timeout = 1 }
                _ = manager.timeout
                _ = manager.debugDescription
            }
        }
        XCTAssertEqual(done.wait(timeout: .now() + 30), .success)
        wait(for: [peerFinished], timeout: 15)
    }
}

private var streamSocket: Int32 {
#if canImport(Darwin)
    SOCK_STREAM
#else
    Int32(SOCK_STREAM.rawValue)
#endif
}

private func makeClient() throws -> (SMB2Client, Int32) {
    var sockets: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, streamSocket, 0, &sockets) == 0 else { throw POSIXError(.EIO) }
    let client = try SMB2Client()
    try client.withThreadSafeContext { context in
        context.pointee.fd = sockets[0]
        context.pointee.credits = 32
        context.pointee.dialect = UInt16(SMB2_VERSION_0302.rawValue)
        context.pointee.max_read_size = 65_536
        context.pointee.max_transact_size = 65_536
    }
    XCTAssertEqual(fcntl(sockets[0], F_SETFL, O_NONBLOCK), 0)
    var deadline = timeval(tv_sec: 8, tv_usec: 0)
    _ = setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &deadline, socklen_t(MemoryLayout<timeval>.size))
#if canImport(Darwin)
    var noSignal: Int32 = 1
    _ = setsockopt(sockets[1], SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
#endif
    client.timeout = 1
    return (client, sockets[1])
}

private func receiveAll(_ fd: Int32, _ count: Int) throws -> Data {
    var data = Data(repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let received = data.withUnsafeMutableBytes {
            recv(fd, $0.baseAddress!.advanced(by: offset), count - offset, 0)
        }
        guard received > 0 else { throw POSIXError(.EIO) }
        offset += received
    }
    return data
}

private func receivePacket(_ fd: Int32) throws -> Data {
    let prefix = try receiveAll(fd, 4)
    let count = prefix.reduce(0) { ($0 << 8) | Int($1) }
    guard count >= 64, count <= 8 << 20 else { throw POSIXError(.EIO) }
    return try receiveAll(fd, count)
}

private func sendAll(_ fd: Int32, _ data: Data) throws {
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

private func response(for request: Data) -> Data {
    var header = Data(request.prefix(64))
    header.put(UInt32(0), at: 8)
    header.put(UInt16(1), at: 14)
    header.put(UInt32(SMB2_FLAGS_SERVER_TO_REDIR), at: 16)
    header.put(UInt32(0), at: 20)
    return header
}

private extension Data {
    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        var value = value.littleEndian
        Swift.withUnsafeBytes(of: &value) { replaceSubrange(offset..<offset + $0.count, with: $0) }
    }

    func number<T: FixedWidthInteger>(at offset: Int, _ type: T.Type) -> T {
        withUnsafeBytes { T(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: type)) }
    }
}
