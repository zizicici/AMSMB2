//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2
#if canImport(System)
import System
#else
import SystemPackage
#endif

extension FileDescriptor {
    static var invalid: FileDescriptor { .init(rawValue: -1) }
    var isValidSocket: Bool { rawValue >= 0 }
}

/// Provides synchronous operation on SMB2
final class SMB2Client: CustomReflectable, @unchecked Sendable {
    private var context: UnsafeMutablePointer<smb2_context>?
    private let _context_lock = NSRecursiveLock()

    /// True only while `smb2_service()` itself is on the stack, so callbacks
    /// it fires can be told apart from callbacks fired during the teardown
    /// inside `service()` (which only carry placeholder statuses). Accessed
    /// on the service thread only; every operation holds the context lock
    /// for its full duration.
    private var isServicing = false

    init() throws {
        self.context = try smb2_init_context().unwrap()
    }

    deinit {
        if isActive {
            try? self.disconnect()
        }
        destroyContext()
    }

    func destroyContext() {
        _context_lock.lock()
        defer { _context_lock.unlock() }
        guard let context else { return }
        self.context = nil
        smb2_destroy_context(context)
    }

    func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R)
        throws -> R
    {
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        guard let context else {
            throw POSIXError(.socketNotConnected, description: "SMB2 context is already destroyed.")
        }
        return try handler(context)
    }

    public var customMirror: Mirror {
        _context_lock.lock()
        defer { _context_lock.unlock() }
        var c: [(label: String?, value: Any)] = []
        if context != nil {
            // server is NULL between context creation and connect.
            c.append((label: "server", value: server ?? ""))
            c.append((label: "securityMode", value: securityMode))
            c.append((label: "authentication", value: authentication))
            clientGuid.map { c.append((label: "clientGuid", value: $0)) }
            c.append((label: "user", value: user))
            c.append((label: "version", value: version))
        }
        c.append((label: "isConnected", value: isActive))
        c.append((label: "timeout", value: timeout))

        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
}

// MARK: Setting manipulation

extension SMB2Client {
    var opaque: UnsafeMutableRawPointer? {
        get {
            try? withThreadSafeContext { smb2_get_opaque($0) }
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_opaque(context, newValue)
            }
        }
    }
    
    var isActive: Bool {
        // Client contexts no longer join libsmb2's server-only active-contexts list,
        // so liveness is just "context allocated and socket valid".
        return fileDescriptor.isValidSocket
    }
    
    var timeout: TimeInterval {
        get {
            (try? withThreadSafeContext { TimeInterval($0.pointee.timeout) }) ?? 0
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_timeout(context, Int32(newValue))
            }
        }
    }
    
    var workstation: String {
        get {
            (try? withThreadSafeContext { smb2_get_workstation($0).map(String.init(cString:)) }) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_workstation(context, newValue)
            }
        }
    }
    
    var domain: String {
        get {
            (try? withThreadSafeContext { smb2_get_domain($0).map(String.init(cString:)) }) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_domain(context, newValue)
            }
        }
    }
    
    var user: String {
        get {
            (try? withThreadSafeContext { smb2_get_user($0).map(String.init(cString:)) }) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_user(context, newValue)
            }
        }
    }
    
    var password: String {
        get {
            (try? withThreadSafeContext { $0.pointee.password.map(String.init(cString:)) }) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_password(context, newValue != "" ? newValue : nil)
            }
        }
    }

    var securityMode: NegotiateSigning {
        get {
            (try? withThreadSafeContext { NegotiateSigning(rawValue: $0.pointee.security_mode) }) ?? []
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_security_mode(context, newValue.rawValue)
            }
        }
    }

    var seal: Bool {
        get {
            (try? withThreadSafeContext { $0.pointee.seal != 0 }) ?? false
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_seal(context, newValue ? 1 : 0)
            }
        }
    }

    var authentication: Security {
        get {
            (try? withThreadSafeContext { $0.pointee.sec }) ?? .undefined
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_authentication(context, .init(bitPattern: newValue.rawValue))
            }
        }
    }

    var clientGuid: UUID? {
        try? withThreadSafeContext { context in
            let guid = try smb2_get_client_guid(context).unwrap()
            let uuid = UnsafeRawPointer(guid).assumingMemoryBound(to: uuid_t.self).pointee
            return UUID(uuid: uuid)
        }
    }

    var server: String? {
        try? withThreadSafeContext { $0.pointee.server.map(String.init(cString:)) }
    }

    var share: String? {
        try? withThreadSafeContext { $0.pointee.share.map(String.init(cString:)) }
    }

    var version: Version {
        (try? withThreadSafeContext { Version(rawValue: UInt32(smb2_get_dialect($0))) }) ?? .any
    }
    
    var passthrough: Bool {
        get {
            (try? withThreadSafeContext { context in
                var result: CInt = 0
                smb2_get_passthrough(context, &result)
                return result != 0
            }) ?? false
        }
        set {
            try? withThreadSafeContext { smb2_set_passthrough($0, newValue ? 1 : 0) }
        }
    }
    
    var fileDescriptor: FileDescriptor {
        (try? withThreadSafeContext { .init(rawValue: smb2_get_fd($0)) }) ?? .invalid
    }

    var errorString: String? {
        try? withThreadSafeContext { smb2_get_error($0).map(String.init(cString:)) }
    }
    
    var ntError: NTStatus {
        (try? withThreadSafeContext { .init(rawValue: smb2_get_nterror($0)) }) ?? .success
    }
    
    var errno: Errno {
        ntError.errno
    }
    
    var maximumTransactionSize: Int {
        (try? withThreadSafeContext { Int($0.pointee.max_transact_size) }) ?? 65535
    }

    func whichEvents() throws -> Int16 {
        try withThreadSafeContext { Int16(truncatingIfNeeded: smb2_which_events($0)) }
    }

    func service(revents: Int32) throws {
        try withThreadSafeContext { context in
            isServicing = true
            let result = smb2_service(context, revents)
            isServicing = false
            if result < 0 {
                let description = errorString
                destroyContext()
                if result == -1 {
                    // smb2_service() signals "connection failed" with a bare
                    // -1; the reason is in the error string, not an errno.
                    // Mapping -1 through errno would misreport EPERM.
                    throw POSIXError(.socketNotConnected, description: description)
                }
                try POSIXError.throwIfError(result, description: description)
            }
        }
    }
}

// MARK: Connectivity

extension SMB2Client {
    func connect(server: String, share: String, user: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_connect_share_async(
                context, server, share, user, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func disconnect() throws {
        _=try? async_await { context, cbPtr -> Int32 in
            smb2_disconnect_share_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }

    func echo() throws {
        if !isActive {
            throw POSIXError(.socketNotConnected, description: nil)
        }
        try async_await { context, cbPtr -> Int32 in
            smb2_echo_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }
}

// MARK: DCE-RPC

extension SMB2Client {
    func shareEnum() throws -> [SMB2Share] {
        try async_await(dataHandler: [SMB2Share].init) { context, cbPtr -> Int32 in
            smb2_share_enum_async(context, SMB2_SHARE_INFO_1, SMB2Client.generic_handler, cbPtr)
        }.data
    }
}


// MARK: File information

extension SMB2Client {
    func stat(_ path: String) throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        try async_await { context, cbPtr -> Int32 in
            smb2_stat_async(context, path.trimmedPath, &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }

    func statvfs(_ path: String) throws -> smb2_statvfs {
        var st = smb2_statvfs()
        try async_await { context, cbPtr -> Int32 in
            smb2_statvfs_async(context, path.trimmedPath, &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }

    func readlink(_ path: String) throws -> String {
        try async_await(dataHandler: String.init) { context, cbPtr -> Int32 in
            smb2_readlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }.data
    }
    
    func symlink(_ path: String, to destination: String) throws {
        // Mirrors libsmb2: an absolute target gets the NT object-manager
        // prefix and must not carry SMB2_SYMLINK_FLAG_RELATIVE, or the
        // server resolves it against the link's own directory
        // ([MS-FSCC] 2.1.2.4).
        let target = destination.replacingOccurrences(of: "/", with: "\\")
        let isAbsolute = target.first == "\\" || target.dropFirst().first == ":"
        let wireTarget = isAbsolute ? "\\??\\" + target : target
        let utf16Bytes = wireTarget.utf16.count * 2
        guard utf16Bytes <= Int(UInt16.max) - 16 else {
            throw POSIXError(.invalidArgument, description: "Symbolic link target is too long.")
        }
        let file = try SMB2FileHandle(
            path: path, .readWrite, options: [.create, .exclusiveCreate, .symlink, .sync], on: self
        )
        let reparse = IOCtl.SymbolicLinkReparse(path: wireTarget, isRelative: !isAbsolute)
        try file.fcntl(command: .setReparsePoint, args: reparse)
    }
}

// MARK: File operation

extension SMB2Client {
    func mkdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_mkdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }

    func rmdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rmdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }
    
    func unlink(_ path: String, type: smb2_stat_64.ResourceType = .file) throws {
        switch type {
        case .directory:
            throw POSIXError(.invalidArgument, description: "Use rmdir() to delete a directory.")
        case .file:
            try async_await { context, cbPtr -> Int32 in
                smb2_unlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
            }
        case .link:
            let file = try SMB2FileHandle(path: path, .readWrite, options: [.symlink], on: self)
            try file.setInfo(smb2_file_disposition_info(delete_pending: 1), infoClass: .disposition)
        default:
            preconditionFailure("Not supported file type.")
        }
    }

    func rename(_ path: String, to newPath: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rename_async(
                context, path.trimmedPath, newPath.trimmedPath, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func resize(_ path: String, to newSize: UInt64) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_truncate_async(
                context, path.trimmedPath, newSize, SMB2Client.generic_handler, cbPtr
            )
        }
    }
}

// MARK: Async operation handler

extension SMB2Client {
    private class CBData {
        var result: Int32 = .init(NTStatus.success.rawValue)
        var isFinished: Bool = false
        var dataHandler: ((UnsafeMutableRawPointer?) -> Void)?
        weak var client: SMB2Client?
        /// Whether the completing callback fired while `smb2_service()` was
        /// on the stack — i.e. it carries this operation's real result (a
        /// delivered reply, or the connect callback with the actual connect
        /// error). Callbacks fired during teardown inside `service()` only
        /// carry placeholder statuses.
        var completedDuringService = false
        var status: NTStatus {
            NTStatus(rawValue: result)
        }

        func finish(status: Int32, commandData: UnsafeMutableRawPointer?) {
            let ntStatus = NTStatus(rawValue: status)
            if ntStatus != .success {
                result = status
            }
            defer {
                dataHandler = nil
                isFinished = true
            }
            guard !ntStatus.deliversErrorReply else {
                // Failed commands deliver a small smb2_error_reply where the caller expects
                // its own reply struct; decoding it would read out of bounds. The payload
                // is freed by smb2_free_pdu() (copychunk-format errors may leak a small
                // output buffer; bounded and accepted).
                return
            }
            dataHandler?(commandData)
        }

        func detachHandler() {
            dataHandler = nil
        }
    }

    private func wait_for_reply(_ cb: CBData) throws {
        let startTime = ProcessInfo.processInfo.systemUptime
        while !cb.isFinished {
            var pfd = pollfd()
            pfd.fd = fileDescriptor.rawValue
            pfd.events = try whichEvents()
            if pfd.fd < 0 {
                // The socket is gone (e.g. closed inside libsmb2); errno is
                // unrelated on this path, so say what actually happened.
                throw POSIXError(.socketNotConnected, description: errorString)
            }
            if poll(&pfd, 1, 1000) < 0, errno != .resourceTemporarilyUnavailable,
                errno != .interrupted
            {
                throw POSIXError(errno, description: errorString)
            }

            // Complete queued PDUs while caller-owned buffers are still alive.
            // A PDU already receiving a partial reply is no longer in these queues;
            // the backstop below must abort its context before unwinding.
            if timeout > 0 {
                smb2_timeout_pdus(try context.unwrap())
            }
            if cb.isFinished {
                destroyContext()
                break
            }

            if timeout > 0, ProcessInfo.processInfo.systemUptime - startTime > timeout + 2 {
                throw POSIXError(.timedOut, description: nil)
            }
            if pfd.revents == 0 { continue }

            do {
                try service(revents: Int32(pfd.revents))
            } catch {
                // A callback that completed while smb2_service() itself ran
                // carries this operation's real result (a delivered reply, or
                // the connect callback with the actual connect error) — keep
                // it; the failure surfaces on the next operation, like
                // libsmb2's own synchronous wait loop. A callback that only
                // completed during the teardown inside service() carries a
                // placeholder status (bare -1, or a negated cancellation);
                // surface the connection failure with its description
                // instead of letting the placeholder degrade into a
                // meaningless errno.
                if cb.completedDuringService { break }
                throw error
            }
        }
    }

    static let generic_handler: smb2_command_cb = { smb2, status, command_data, cbdata in
        guard let cbdata else { return }
        let callbackData = Unmanaged<CBData>.fromOpaque(cbdata).takeRetainedValue()
        callbackData.completedDuringService = callbackData.client?.isServicing ?? false
        do {
            guard try smb2.unwrap().pointee.fd >= 0 else {
                // Connect-stage failures and context teardown close the socket before
                // invoking us; record the status instead of swallowing it as success.
                callbackData.result = status
                callbackData.detachHandler()
                callbackData.isFinished = true
                return
            }
            callbackData.finish(status: status, commandData: command_data)
        } catch {
            callbackData.result = status
            callbackData.detachHandler()
            callbackData.isFinished = true
        }
    }

    typealias ContextHandler<R> = (_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?)
        throws -> R
    typealias UnsafeContextHandler<R> = (
        _ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?
    ) throws -> R

    private func abortRequest(_ cb: CBData, pointer: UnsafeMutableRawPointer) {
        cb.detachHandler()
        // Teardown closes the socket and aborts queued AND partially received PDUs.
        // It must finish before the caller's read/write buffers leave scope.
        destroyContext()
        if !cb.isFinished {
            // Teardown cannot call us again, even if setup never registered a callback.
            Unmanaged<CBData>.fromOpaque(pointer).release()
        }
    }

    /// The setup call failed synchronously: nothing of this request was
    /// queued, so no teardown is needed — destroying the context here would
    /// needlessly kill a live connection over e.g. an invalid argument.
    private func cancelRequest(_ cb: CBData, pointer: UnsafeMutableRawPointer) {
        cb.detachHandler()
        Unmanaged<CBData>.fromOpaque(pointer).release()
    }

    @discardableResult
    func async_await(execute handler: UnsafeContextHandler<Int32>) throws -> Int32 {
        try async_await(dataHandler: { _, _ in }, execute: handler).result
    }

    @discardableResult
    func async_await<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<Int32>
    )
        throws -> (result: Int32, data: DataType)
    {
        try withThreadSafeContext { context -> (Int32, DataType) in
            let cb = CBData()
            cb.client = self
            let cbPtr = Unmanaged.passRetained(cb).toOpaque()
            var resultData: DataType?
            var dataHandlerError: (any Error)?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(self, ptr)
                } catch {
                    dataHandlerError = error
                }
            }

            let result: Int32
            do {
                result = try handler(context, cbPtr)
                try POSIXError.throwIfError(result, description: errorString)
            } catch {
                // Nothing was queued on our behalf; keep the connection.
                cancelRequest(cb, pointer: cbPtr)
                throw error
            }

            do {
                try wait_for_reply(cb)
            } catch {
                abortRequest(cb, pointer: cbPtr)
                throw error
            }
            let cbResult = cb.result

            // PDU timeout, teardown and fd-guard callbacks deliver raw NT statuses, while
            // libsmb2's internal callbacks deliver small negative errnos (bit pattern
            // 0xFFFF_FFxx). Map NT-shaped results via NTStatus so e.g. IO_TIMEOUT surfaces
            // as ETIMEDOUT with its NT token instead of degrading to a meaningless ECANCELED.
            if cbResult < 0, UInt32(bitPattern: cbResult) < 0xFFFF_0000 {
                let status = NTStatus(rawValue: cbResult)
                if status.severity != .success {
                    throw POSIXError(status.errno, description: String(describing: status))
                }
            }
            try POSIXError.throwIfError(cbResult, description: errorString)
            if let error = dataHandlerError { throw error }
            return try (cbResult, resultData.unwrap())
        }
    }

    @discardableResult
    func async_await_pdu(execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>)
        throws -> UInt32
    {
        try async_await_pdu(dataHandler: { _, _ in }, execute: handler).status
    }

    @discardableResult
    func async_await_pdu<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>
    )
        throws -> (status: UInt32, data: DataType)
    {
        try withThreadSafeContext { context -> (UInt32, DataType) in
            let cb = CBData()
            cb.client = self
            let cbPtr = Unmanaged.passRetained(cb).toOpaque()
            var resultData: DataType?
            var dataHandlerError: (any Error)?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(self, ptr)
                } catch {
                    dataHandlerError = error
                }
            }

            let pdu: UnsafeMutablePointer<smb2_pdu>
            do {
                pdu = try handler(context, cbPtr).unwrap()
            } catch {
                // Nothing was queued on our behalf; keep the connection.
                cancelRequest(cb, pointer: cbPtr)
                throw error
            }
            smb2_queue_pdu(context, pdu)
            do {
                try wait_for_reply(cb)
            } catch {
                abortRequest(cb, pointer: cbPtr)
                throw error
            }

            try cb.status.throwIfError()
            if let error = dataHandlerError { throw error }
            return try (cb.status.rawValue, resultData.unwrap())
        }
    }
}

extension SMB2Client {
    struct NegotiateSigning: OptionSet, Sendable, CustomStringConvertible {
        var rawValue: UInt16
        
        var description: String {
            var result: [String] = []
            if contains(.enabled) { result.append("Enabled") }
            if contains(.required) { result.append("Required") }
            return result.joined(separator: ", ")
        }
        
        static let enabled = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_ENABLED)
        static let required = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_REQUIRED)
    }

    typealias Version = smb2_negotiate_version
    typealias Security = smb2_sec
}

extension SMB2.smb2_negotiate_version: Swift.Hashable, Swift.CustomStringConvertible {
    static let any = SMB2_VERSION_ANY
    static let v2 = SMB2_VERSION_ANY2
    static let v3 = SMB2_VERSION_ANY3
    static let v2_02 = SMB2_VERSION_0202
    static let v2_10 = SMB2_VERSION_0210
    static let v3_00 = SMB2_VERSION_0300
    static let v3_02 = SMB2_VERSION_0302
    static let v3_11 = SMB2_VERSION_0311
    
    public var description: String {
        switch self {
        case .any: return "Any"
        case .v2: return "2.0"
        case .v3: return "3.0"
        case .v2_02: return "2.02"
        case .v2_10: return "2.10"
        case .v3_00: return "3.00"
        case .v3_02: return "3.02"
        case .v3_11: return "3.11"
        default: return "Unknown"
        }
    }

    static func ==(lhs: smb2_negotiate_version, rhs: smb2_negotiate_version) -> Bool {
        lhs.rawValue == rhs.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}

extension SMB2.smb2_sec: Swift.Hashable, Swift.CustomStringConvertible {
    static let undefined = SMB2_SEC_UNDEFINED
    static let ntlmSsp = SMB2_SEC_NTLMSSP
    static let kerberos5 = SMB2_SEC_KRB5
    
    public var description: String {
        switch self {
        case .undefined: return "Undefined"
        case .ntlmSsp: return "NTLM SSP"
        case .kerberos5: return "Kerberos5"
        default: return "Unknown"
        }
    }

    static func ==(lhs: smb2_sec, rhs: smb2_sec) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
}

struct SMB2Share {
    let name: String
    let props: ShareProperties
    let comment: String
}

struct ShareProperties: RawRepresentable {
    enum ShareType: UInt32 {
        case diskTree
        case printQueue
        case device
        case ipc
    }

    let rawValue: UInt32

    var type: ShareType {
        // Non-conformant servers can set undefined low bits; default to disk share.
        ShareType(rawValue: rawValue & 0x0fff_ffff) ?? .diskTree
    }

    var isTemporary: Bool {
        rawValue & UInt32(bitPattern: SMB2_SHARE_TYPE_TEMPORARY) != 0
    }

    var isHidden: Bool {
        rawValue & SMB2_SHARE_TYPE_HIDDEN != 0
    }
}

struct NTStatus: LocalizedError, Hashable, CustomStringConvertible, Sendable {
    enum Severity: UInt32, Hashable, CustomStringConvertible, Sendable {
        case success
        case info
        case warning
        case error
        
        var description: String {
            switch self {
            case .success: return "Success"
            case .info: return "Info"
            case .warning: return "Warning"
            case .error: return "Error"
            }
        }
        
        init(status: NTStatus) {
            self = switch status.rawValue & SMB2_STATUS_SEVERITY_MASK {
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_SUCCESS):
                .success
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_INFO):
                .info
            case SMB2_STATUS_SEVERITY_WARNING:
                .warning
            case SMB2_STATUS_SEVERITY_ERROR:
                .error
            default:
                .success
            }
        }
    }
    
    let rawValue: UInt32
    
    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    var description: String {
        "Error 0x\(String(rawValue, radix: 16, uppercase: true)): \(localizedDescription)"
    }
    
    var errorDescription: String? {
        nterror_to_str(rawValue).map(String.init(cString:))
    }
    
    var errno: Errno {
        .init(rawValue: nterror_to_errno(rawValue))
    }
    
    var severity: Severity {
        .init(status: self)
    }
    
    func throwIfError() throws {
        if severity == .error {
            throw POSIXError(errno,description: description)
        }
    }

    // Mirrors the severity half of libsmb2's smb2_is_error_response(): which
    // statuses deliver an smb2_error_reply payload instead of the command's own
    // reply struct. (The IOCTL-reply-format exception for copychunk errors is
    // not mirrored; skipping their decode is the safe direction.)
    var deliversErrorReply: Bool {
        switch severity {
        case .error:
            return rawValue != SMB2_STATUS_MORE_PROCESSING_REQUIRED
        case .warning:
            return rawValue == SMB2_STATUS_STOPPED_ON_SYMLINK
        default:
            return false
        }
    }
    
    static let success = Self(rawValue: SMB2_STATUS_SUCCESS)
}
