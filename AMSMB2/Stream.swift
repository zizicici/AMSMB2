//
//  Stream.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/14/24.
//  Copyright © 2024 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation

extension Stream {
    func withOpenStream(_ handler: () throws -> Void) rethrows {
        let shouldCloseStream = streamStatus == .notOpen
        if streamStatus == .notOpen {
            open()
        }
        defer {
            if shouldCloseStream {
                close()
            }
        }
        try handler()
    }
    
    func withOpenStream(_ handler: () async throws -> Void) async rethrows {
        let shouldCloseStream = streamStatus == .notOpen
        if streamStatus == .notOpen {
            open()
        }
        defer {
            if shouldCloseStream {
                close()
            }
        }
        try await handler()
    }
}

extension InputStream {
    func readData(maxLength length: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: length)
        let result = read(&buffer, maxLength: buffer.count)
        if result < 0 {
            throw streamError ?? POSIXError(.ioError, description: "Unknown stream error.")
        } else {
            return Data(buffer.prefix(result))
        }
    }
}

extension OutputStream {
    func write<DataType: DataProtocol>(_ data: DataType) throws -> Int {
        var buffer = Array(data)
        let result = write(&buffer, maxLength: buffer.count)
        if result < 0 {
            throw streamError ?? POSIXError(.ioError, description: "Unknown stream error.")
        } else {
            return result
        }
    }
}

extension AsyncThrowingStream where Element == Data, Failure == any Error {
    init(url: URL, chunkSize: Int = 1_048_576) {
        self.init { continuation in
            do {
                let fileHandle = try FileHandle(forReadingFrom: url)
                defer {
                    try? fileHandle.close()
                }

                while true {
                    let data: Data?
                    if #available(macOS 10.15.4, iOS 13.4, watchOS 6.2, tvOS 13.4, *) {
                        data = try fileHandle.read(upToCount: chunkSize)
                    } else {
                        data = fileHandle.readData(ofLength: chunkSize)
                    }
                    if let data = data, !data.isEmpty {
                        continuation.yield(data)
                    } else {
                        break
                    }
                }
                continuation.finish()
            } catch {
                continuation.finish(throwing: error)
            }
        }
    }
    
    func write(toFileAt file: URL) async throws {
        guard let stream = OutputStream(url: file, append: false) else {
            throw POSIXError(.noSuchFileOrDirectory, description: nil)
        }
        try await stream.withOpenStream {
            for try await data in self {
                let written = try stream.write(data)
                guard written == data.count else {
                    throw POSIXError(.ioError, description: "Short write to destination file.")
                }
            }
        }
    }
}

/// Prefetch pauses once this many bytes are buffered, so a fast producer
/// cannot grow an AsyncInputStream's buffer without bound.
private let asyncInputStreamHighWaterMark = 4 << 20

/// Erases a non-Sendable iterator for the one task that consumes it.
private struct SendableEraser: @unchecked Sendable {
    let value: Any
    init(_ value: Any) { self.value = value }
}

public class AsyncInputStream<Seq>: InputStream, @unchecked Sendable where Seq: AsyncSequence, Seq.Element: DataProtocol, Seq: SendableMetatype, Seq.Element: SendableMetatype, Seq.AsyncIterator: SendableMetatype {
    private var stream: Seq
    private var iterator: Seq.AsyncIterator
    private let condition = NSCondition()

    // All guarded by `condition`. `buffer` is only ever grown by append and
    // reset as a whole, so its indices stay zero-based; consumption is
    // tracked with `bufferOffset` instead of re-slicing.
    private var buffer = Data()
    private var bufferOffset = 0
    private var isProducerFinished = false
    private var producerError: (any Error)?
    private var status: Stream.Status = .notOpen
    private var theError: (any Error)?

    /// Prefetch pauses once this many bytes are buffered, so a fast producer
    /// cannot grow the buffer without bound.
    private var highWaterMark: Int { asyncInputStreamHighWaterMark }

    init(stream: Seq) {
        self.stream = stream
        self.iterator = stream.makeAsyncIterator()
        super.init(data: Data())
        prefetchData()
    }

    override public var streamStatus: Stream.Status {
        condition.lock()
        defer { condition.unlock() }
        return status
    }

    override public var streamError: (any Error)? {
        condition.lock()
        defer { condition.unlock() }
        return theError
    }

    override public func open() {
        condition.lock()
        if status == .notOpen {
            status = .open
        }
        condition.unlock()
    }

    override public func close() {
        condition.lock()
        status = .closed
        condition.broadcast()
        condition.unlock()
    }

    override public func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        condition.lock()
        defer { condition.unlock() }
        guard len > 0 else { return 0 }

        while true {
            switch status {
            case .notOpen, .opening, .closed, .error:
                return -1
            case .atEnd:
                return 0
            case .open, .reading, .writing:
                break
            @unknown default:
                return -1
            }

            if bufferOffset < self.buffer.count {
                let count = min(len, self.buffer.count - bufferOffset)
                self.buffer.withUnsafeBytes { raw in
                    _ = memcpy(buffer, raw.baseAddress! + bufferOffset, count)
                }
                bufferOffset += count
                if bufferOffset == self.buffer.count {
                    self.buffer.removeAll()
                    bufferOffset = 0
                    if isProducerFinished {
                        // Draining after the producer ended decides the
                        // terminal state: an error must surface through the
                        // next read, never decay into EOF.
                        if let error = producerError {
                            theError = error
                            status = .error
                        } else {
                            status = .atEnd
                        }
                    }
                }
                return count
            }

            // Buffer drained. Block until the producer delivers, finishes or
            // fails; EOF must never be reported while the sequence can still
            // yield.
            if isProducerFinished {
                if let error = producerError {
                    theError = error
                    status = .error
                    return -1
                }
                status = .atEnd
                return 0
            }
            _ = condition.wait(until: Date().addingTimeInterval(0.05))
        }
    }

    override public var hasBytesAvailable: Bool {
        condition.lock()
        defer { condition.unlock() }
        return bufferOffset < buffer.count || (!isProducerFinished && status == .open)
    }

    // Synchronous helpers so NSCondition stays out of async contexts.

    private func prefetchHasSpace(for count: Int) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        let buffered = buffer.count - bufferOffset
        // An empty buffer always accepts, even an oversized chunk: a single
        // element larger than the mark would otherwise wait for space that
        // can never free up (the consumer cannot drain what was never
        // buffered) and deadlock the stream.
        return buffered == 0 || buffered + count <= highWaterMark
    }

    private func prefetchIsClosed() -> Bool {
        condition.lock()
        defer { condition.unlock() }
        return status == .closed
    }

    /// Appends a chunk, waking a blocked reader. Returns false when the
    /// stream was closed and the chunk is dropped.
    private func prefetchAppend(_ chunk: Data) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard status != .closed else { return false }
        // Release the consumed prefix before growing: otherwise a fast
        // producer and a slow reader keep every byte resident until the
        // buffer is fully drained, which for a large stream never happens.
        if bufferOffset > 0 {
            buffer.removeFirst(bufferOffset)
            bufferOffset = 0
        }
        buffer.append(chunk)
        condition.broadcast()
        return true
    }

    private func producerDidFinish(error: (any Error)?) {
        condition.lock()
        defer { condition.unlock() }
        isProducerFinished = true
        if let error {
            producerError = error
        }
        condition.broadcast()
    }

    private func prefetchData() {
        // [weak self]: a producer parked in next() forever must not pin the
        // stream (and its residual buffer) after the consumer went away.
        // self is re-resolved per block, so the strong reference only spans
        // the chunk handoff, never the await.
        // Seq.AsyncIterator is only SendableMetaatype-constrained; the
        // unchecked cast mirrors how init() already hands the sequence to
        // this task. The iterator is confined to this one task.
        let capturedIterator = SendableEraser(iterator)
        Task { @Sendable [weak self] in
            var iterator = capturedIterator.value as! Seq.AsyncIterator
            while true {
                do {
                    guard let data = try await iterator.next() else { break }
                    spaceWait: while true {
                        guard let self else { return }
                        if self.prefetchHasSpace(for: Data(data).count) { break spaceWait }
                        guard !self.prefetchIsClosed() else { return }
                        try? await Task.sleep(nanoseconds: 20_000_000)
                    }
                    guard let self else { return }
                    let chunk = Data(data)
                    guard self.prefetchAppend(chunk) else { return }
                } catch {
                    guard let self else { return }
                    self.producerDidFinish(error: error)
                    return
                }
            }
            guard let self else { return }
            self.producerDidFinish(error: nil)
        }
    }
}
