//
//  SMB2RegressionTests.swift
//  AMSMB2
//
//  Regression tests for issues found in the full-repository review:
//  each asserts the fixed behavior.
//
//  Distributed under MIT license.
//

import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
#if canImport(System)
import System
#else
import SystemPackage
import FoundationNetworking
#endif
@testable import AMSMB2
import SMB2

final class SMB2RegressionTests: XCTestCase {
    // MARK: contents(atPath:range:) must fail fast when not connected

    func test_contentsAsyncStreamFailsWhenNotConnected() {
        let manager = SMB2Manager(url: URL(string: "smb://127.0.0.1")!, credential: nil)!
        let stream = manager.contents(atPath: "file", range: 0..<16)
        let finished = expectation(description: "stream finished")
        Task {
            var iterator = stream.makeAsyncIterator()
            do {
                _ = try await iterator.next()
                XCTFail("Expected the stream to fail instead of hanging or yielding")
            } catch {
                XCTAssertEqual((error as? POSIXError)?.code, .ENOTCONN)
            }
            finished.fulfill()
        }
        wait(for: [finished], timeout: 2)
    }

    // MARK: AsyncInputStream bridges async producers with blocking semantics

    func test_AsyncInputStreamReadWaitsForFirstChunk() {
        let base = AsyncStream<Data> { continuation in
            Task {
                try? await Task.sleep(nanoseconds: 300_000_000)
                continuation.yield(Data([1, 2, 3]))
                continuation.finish()
            }
        }
        let stream = AsyncInputStream(stream: base)
        stream.open()
        var buffer = [UInt8](repeating: 0, count: 16)
        // Blocks until the chunk arrives instead of failing with -1.
        let count = stream.read(&buffer, maxLength: buffer.count)
        XCTAssertEqual(count, 3)
        XCTAssertEqual(Array(buffer.prefix(3)), [1, 2, 3])
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 0, "real EOF after the producer finished")
        XCTAssertEqual(stream.streamStatus, .atEnd)
    }

    func test_AsyncInputStreamDoesNotSignalEOFWhileProducerYields() {
        let base = AsyncStream<Data> { continuation in
            continuation.yield(Data([1, 2, 3]))
            Task {
                try? await Task.sleep(nanoseconds: 800_000_000)
                continuation.yield(Data([4, 5, 6]))
                continuation.finish()
            }
        }
        let stream = AsyncInputStream(stream: base)
        stream.open()
        Thread.sleep(forTimeInterval: 0.2) // first chunk is buffered
        var buffer = [UInt8](repeating: 0, count: 16)
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3)
        XCTAssertEqual(stream.streamStatus, .open, "a drained buffer is not EOF while the producer can still yield")
        Thread.sleep(forTimeInterval: 1.0) // second chunk arrives and the sequence finishes
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3)
        XCTAssertEqual(Array(buffer.prefix(3)), [4, 5, 6])
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 0)
    }

    func test_AsyncInputStreamPropagatesProducerErrorAfterDrain() {
        // Deterministic ordering: the first chunk is read out before the
        // producer is failed, so the failure can only surface on the next
        // read. read() blocks until the chunk arrives, no polling needed.
        let (base, producer) = AsyncThrowingStream<Data, any Error>.makeStream()
        let stream = AsyncInputStream(stream: base)
        stream.open()
        producer.yield(Data([1, 2, 3]))
        var buffer = [UInt8](repeating: 0, count: 16)
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3, "buffered data stays readable before the error")
        producer.finish(throwing: POSIXError(.EIO))
        // Blocks until the producer failure surfaces, then reports it.
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), -1)
        XCTAssertEqual(stream.streamStatus, .error)
        XCTAssertNotNil(stream.streamError)
    }

    func test_AsyncInputStreamErrorBeforeDrainIsNotEOF() {
        // The producer fails before the buffered chunk is consumed: draining
        // the buffer must not decay the stream into EOF and swallow the error.
        let (base, producer) = AsyncThrowingStream<Data, any Error>.makeStream()
        let stream = AsyncInputStream(stream: base)
        stream.open()
        producer.yield(Data([1, 2, 3]))
        producer.finish(throwing: POSIXError(.EIO))
        Thread.sleep(forTimeInterval: 0.2) // both the chunk and the failure are recorded
        var buffer = [UInt8](repeating: 0, count: 16)
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3, "buffered data is still delivered")
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), -1, "the failure surfaces after the buffer drains")
        XCTAssertEqual(stream.streamStatus, .error)
        XCTAssertNotNil(stream.streamError)
    }

    func test_AsyncInputStreamAcceptsOversizedChunk() {
        // A single element larger than the prefetch high-water mark must not
        // deadlock the stream waiting for space that can never free up.
        let oversized = 5 << 20
        let base = AsyncStream<Data> { continuation in
            continuation.yield(Data(repeating: 0x41, count: oversized))
            continuation.finish()
        }
        let stream = AsyncInputStream(stream: base)
        stream.open()
        let finished = expectation(description: "oversized chunk fully read")
        DispatchQueue.global().async {
            defer {
                stream.close() // stop the prefetch task on failure paths too
                finished.fulfill()
            }
            var total = 0
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 {
                    XCTAssertEqual(count, 0, "expected EOF, got an error")
                    break
                }
                total += count
            }
            XCTAssertEqual(total, oversized)
        }
        wait(for: [finished], timeout: 10)
    }

    func test_AsyncInputStreamCloseInterruptsBlockedRead() {
        let base = AsyncStream<Data> { continuation in
            // Never yields, never finishes.
        }
        let stream = AsyncInputStream(stream: base)
        stream.open()
        let readReturned = expectation(description: "blocked read returned")
        DispatchQueue.global().async {
            var buffer = [UInt8](repeating: 0, count: 16)
            let count = stream.read(&buffer, maxLength: buffer.count)
            XCTAssertEqual(count, -1, "close() must interrupt a blocked read")
            readReturned.fulfill()
        }
        Thread.sleep(forTimeInterval: 0.2)
        stream.close()
        wait(for: [readReturned], timeout: 2)
    }

    // MARK: customMirror shows domain/workstation only when set, once each

    func test_customMirrorWorkstationAndDomain() {
        let empty = SMB2Manager(url: URL(string: "smb://127.0.0.1")!, credential: nil)!
        XCTAssertEqual(
            empty.debugDescription.components(separatedBy: "workstation").count - 1, 0,
            "workstation is not shown when empty"
        )
        XCTAssertEqual(
            empty.debugDescription.components(separatedBy: "domain").count - 1, 0,
            "domain is not shown when empty"
        )

        let credential = URLCredential(user: "host\\user", password: "", persistence: .forSession)
        let set = SMB2Manager(url: URL(string: "smb://127.0.0.1")!, credential: credential)!
        let description = set.debugDescription
        XCTAssertEqual(description.components(separatedBy: "workstation").count - 1, 1)
        XCTAssertEqual(description.components(separatedBy: "domain").count - 1, 0, "no domain in this credential")
    }

    // MARK: an op whose reply was delivered must succeed despite a following socket failure

    func test_ReadSucceedsWhenSocketFailsAfterReply() throws {
        let (client, peer) = try makeClient()
        let finished = expectation(description: "Late garbage peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                let request = try receivePacket(peer)
                XCTAssertEqual(request.number(at: 12, UInt16.self), UInt16(SMB2_READ.rawValue))
                // A complete READ reply: data starts at absolute offset 80,
                // so the body must be 16 bytes before the data.
                let count = 16
                var body = Data(repeating: 0, count: 16)
                body.put(UInt16(17), at: 0)
                body[2] = 80
                body.put(UInt32(count), at: 4)
                var reply = response(for: request) + body + Data(repeating: 0x41, count: count)
                var length = UInt32(reply.count).bigEndian
                reply = withUnsafeBytes(of: &length) { Data($0) } + reply
                // ...immediately followed by garbage (a "reply" without the
                // server-to-redirector flag) in the same burst, so one
                // smb2_service() call processes both.
                var garbageHeader = response(for: request)
                garbageHeader.put(UInt32(0), at: 16) // clear SMB2_FLAGS_SERVER_TO_REDIR
                var garbage = garbageHeader
                var garbageLength = UInt32(garbage.count).bigEndian
                garbage = withUnsafeBytes(of: &garbageLength) { Data($0) } + garbage
                try sendAll(peer, reply + garbage)
                var byte: UInt8 = 0
                _ = recv(peer, &byte, 1, 0)
            } catch {
                XCTFail("Garbage peer: \(error)")
            }
        }
        defer {
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        // The read itself completed before the connection failed; it must
        // succeed (the failure surfaces on the next operation, like libsmb2's
        // own synchronous loop).
        let data = try file.read(length: 64)
        XCTAssertEqual(data, Data(repeating: 0x41, count: 16))
        XCTAssertFalse(client.isActive)
        XCTAssertThrowsError(try client.echo())
    }

    // MARK: changeNotify semantics: bounded by the PDU timeout, connection torn down

    func test_changeNotifyCappedByTimeout() throws {
        let (client, peer) = try makeClient()
        let finished = expectation(description: "Notify peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                _ = try receivePacket(peer) // the CHANGE_NOTIFY request itself
                var byte: UInt8 = 0
                XCTAssertEqual(recv(peer, &byte, 1, 0), 0, "Client must close the timed out connection")
            } catch {
                XCTFail("Notify peer: \(error)")
            }
        }
        defer {
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        XCTAssertThrowsError(try file.changeNotify(for: .fileName)) { error in
            XCTAssertEqual((error as? POSIXError)?.code, .ETIMEDOUT)
        }
        XCTAssertFalse(client.isActive, "the monitor's PDU timeout tears down the whole connection")
    }

    // MARK: a pending request on a dropped connection reports ENOTCONN, not a bare EPERM

    func test_ReadThrowsNotConnectedWhenSocketDropsWithoutReply() throws {
        let (client, peer) = try makeClient()
        let finished = expectation(description: "Closing peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                _ = try receivePacket(peer) // the READ request itself
                // No reply at all: the socket just dies while the request is
                // in flight (the common disconnect scenario).
            } catch {
                XCTFail("Closing peer: \(error)")
            }
        }
        defer {
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        XCTAssertThrowsError(try file.read(length: 64)) { error in
            XCTAssertEqual(
                (error as? POSIXError)?.code,
                .ENOTCONN,
                "teardown of a still-pending request must surface the connection failure, not a placeholder EPERM"
            )
        }
        XCTAssertFalse(client.isActive)
    }

    // MARK: teardown sweeps handles the caller never closed

    func test_DestroyContextSweepsUnclosedHandles() throws {
        // smb2_destroy_context() promises to free any open smb2fh/smb2dir.
        // Open handles and drop them without closing: the teardown must sweep
        // them (under ASan: exactly once, no double free, no corruption).
        let (client, peer) = try makeClient()
        let finished = expectation(description: "sweep peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            var byte: UInt8 = 0
            _ = recv(peer, &byte, 1, 0) // context torn down without traffic
        }
        var handles = [SMB2FileHandle]()
        for _ in 0..<64 {
            handles.append(try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client))
        }
        handles.removeAll()
        client.destroyContext()
        XCTAssertFalse(client.isActive)
        wait(for: [finished], timeout: 10)
    }

    // MARK: a reply delivered right before the peer hangs up must survive

    func test_ReadSucceedsWhenPeerClosesRightAfterReply() throws {
        // POLLIN|POLLHUP are reported together when the peer answers and
        // immediately closes: the reply sitting in the socket buffer must be
        // processed (fork "drain POLLHUP input") instead of being discarded
        // in favor of a connection error — that would report a write the
        // server already performed as failed.
        let (client, peer) = try makeClient()
        let finished = expectation(description: "Closing-after-reply peer finished")
        DispatchQueue.global().async {
            defer { _ = close(peer); finished.fulfill() }
            do {
                let request = try receivePacket(peer)
                XCTAssertEqual(request.number(at: 12, UInt16.self), UInt16(SMB2_READ.rawValue))
                let count = 16
                var body = Data(repeating: 0, count: 16)
                body.put(UInt16(17), at: 0)
                body[2] = 80
                body.put(UInt32(count), at: 4)
                var reply = response(for: request) + body + Data(repeating: 0x42, count: count)
                var length = UInt32(reply.count).bigEndian
                reply = withUnsafeBytes(of: &length) { Data($0) } + reply
                try sendAll(peer, reply)
                // The reply lands and the socket dies in the same burst; the
                // kernel reports POLLIN|POLLHUP together.
            } catch {
                XCTFail("Reply-then-close peer: \(error)")
            }
        }
        let file = try SMB2FileHandle(fileDescriptor: UUID().uuid, on: client)
        defer {
            client.destroyContext()
            wait(for: [finished], timeout: 10)
        }
        let data = try file.read(length: 64)
        XCTAssertEqual(data, Data(repeating: 0x42, count: 16))
    }

    // MARK: fd 0 is a valid socket

    func test_FileDescriptorZeroIsValidSocket() {
        XCTAssertTrue(FileDescriptor(rawValue: 0).isValidSocket)
        XCTAssertFalse(FileDescriptor.invalid.isValidSocket)
    }

    // MARK: notify chain is traversed exactly once per entry and freed

    func test_NotifyChainTraversalAndFree() throws {
        let client = try SMB2Client()
        defer { client.destroyContext() }

        func makeNode(_ name: String, action: UInt32)
            -> UnsafeMutablePointer<smb2_file_notify_change_information>
        {
            let node = UnsafeMutablePointer<smb2_file_notify_change_information>.allocate(capacity: 1)
            // strdup so the name is freed by C's free(), matching the
            // chain's ownership contract exactly.
            node.initialize(
                to: smb2_file_notify_change_information(action: action, name: strdup(name), next: nil)
            )
            return node
        }

        // three linked entries
        let first = makeNode("first", action: 3)
        let second = makeNode("second", action: 2)
        let third = makeNode("third", action: 1)
        first.pointee.next = second
        second.pointee.next = third

        // The initializer takes ownership of the chain and frees it via
        // free_smb2_file_notify_change_information(); do not touch it after.
        let changes = try [SMB2FileChangeInfo](client, first)
        // Exactly one entry per node: the old loop duplicated the first and
        // dropped the last.
        XCTAssertEqual(changes.count, 3)
        XCTAssertEqual(changes[0].fileName, "first")
        XCTAssertEqual(changes[0].action.rawValue, 3)
        XCTAssertEqual(changes[1].fileName, "second")
        XCTAssertEqual(changes[2].fileName, "third")
    }

    // MARK: queue-time encryption abort completes the compound immediately

    func test_StatWithSealButNoKeyFailsFast() throws {
        // With seal negotiated but no session key, smb2_queue_pdu() fails to
        // encrypt and aborts the whole compound before it is sent. The
        // members' callbacks must fire at once (libsmb2 fork commit
        // "complete compound state on queue-time aborts") with
        // SMB2_STATUS_SHUTDOWN, which maps to EIO (not EPERM/ENOTCONN).
        let client = try SMB2Client()
        defer { client.destroyContext() }
        try client.withThreadSafeContext { context in
            context.pointee.seal = 1
            context.pointee.fd = -1
        }
        client.timeout = 5
        let started = Date()
        XCTAssertThrowsError(try client.stat("file")) { error in
            // The STATUS_SHUTDOWN in the description proves the compound
            // members actually fired; without the fork fix the callback never
            // runs and the caller sees a bare ENOTCONN from the dead socket.
            XCTAssertEqual((error as? POSIXError)?.code, .EIO)
            XCTAssertTrue(
                (error as? POSIXError)?.localizedDescription.contains("SHUTDOWN") == true,
                "expected the teardown status in the description, got: \(error)"
            )
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 3, "must fail immediately, not via the timeout backstop")
    }

    // MARK: a refused connect surfaces ECONNREFUSED on every platform

    func test_ConnectRefusedSurfacesConnectionRefused() throws {
        // Reserve a port and release it again: connecting to the now-unbound
        // port is refused. macOS reports that as POLLHUP (without POLLERR),
        // and the connect callback must still complete with the real socket
        // error instead of a teardown placeholder (which used to degrade
        // into ENODATA "Invalid/Empty data." at the public API).
        let reserved = socket(AF_INET, streamSocket, 0)
        guard reserved >= 0 else { throw POSIXError(.EIO) }
        defer { _ = close(reserved) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let addressSize = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(reserved, $0, addressSize)
            }
        }
        XCTAssertEqual(bound, 0)
        var size = addressSize
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(reserved, $0, &size) }
        }
        XCTAssertEqual(named, 0)
        let port = UInt16(bigEndian: address.sin_port)
        _ = close(reserved) // release: the port is unbound, connects get RST

        let manager = SMB2Manager(url: URL(string: "smb://127.0.0.1:\(port)")!, credential: nil)!
        manager.timeout = 5
        let finished = expectation(description: "connect failed")
        manager.connectShare(name: "share") { error in
            defer { finished.fulfill() }
            guard let posixError = error as? POSIXError else {
                return XCTFail("Expected a POSIXError, got: \(String(describing: error))")
            }
            XCTAssertEqual(posixError.code, .ECONNREFUSED, "\(posixError)")
        }
        wait(for: [finished], timeout: 15)
    }
}

// Socketpair helpers mirroring SMB2LifetimeTests (file-private there).
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
    guard count >= 64, count <= 65_536 else { throw POSIXError(.EIO) }
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
