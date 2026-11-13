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
                try? await Task.sleep(nanoseconds: 300_000_000)
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
        Thread.sleep(forTimeInterval: 0.6) // second chunk arrives and the sequence finishes
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3)
        XCTAssertEqual(Array(buffer.prefix(3)), [4, 5, 6])
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 0)
    }

    func test_AsyncInputStreamPropagatesProducerError() {
        let base = AsyncThrowingStream<Data, any Error> { continuation in
            continuation.yield(Data([1, 2, 3]))
            Task {
                try? await Task.sleep(nanoseconds: 200_000_000)
                continuation.finish(throwing: POSIXError(.EIO))
            }
        }
        let stream = AsyncInputStream(stream: base)
        stream.open()
        Thread.sleep(forTimeInterval: 0.2)
        var buffer = [UInt8](repeating: 0, count: 16)
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), 3, "buffered data stays readable before the error")
        // Blocks until the producer failure surfaces, then reports it.
        XCTAssertEqual(stream.read(&buffer, maxLength: buffer.count), -1)
        XCTAssertEqual(stream.streamStatus, .error)
        XCTAssertNotNil(stream.streamError)
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
