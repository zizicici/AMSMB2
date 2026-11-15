//
//  FileHandle.swift
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

typealias smb2fh = OpaquePointer

@inlinable
var _O_SYNC: CInt { O_SYNC }


#if os(Linux) || os(Android) || os(OpenBSD)
@usableFromInline
let O_SYMLINK: CInt = O_NOFOLLOW
#endif
@inlinable
var _O_SYMLINK: CInt { O_SYMLINK }

extension FileDescriptor.OpenOptions {
    /// Indicates that each write operation is synchronous.
    ///
    /// If this option is specified,
    /// each time you write to the file,
    /// the new data is written immediately and synchronously to the disk.
    ///
    /// The corresponding C constant is `O_SYNC`.
    @_alwaysEmitIntoClient
    public static var sync: FileDescriptor.OpenOptions {
        .init(rawValue: _O_SYNC)
    }
    
    @_alwaysEmitIntoClient
    @available(*, unavailable, renamed: "sync")
    @_disfavoredOverload
    public static var O_SYNC: FileDescriptor.OpenOptions {
        // O_SYNC is defined in compat.h in libsmb so available on all platforms
        sync
    }

#if !canImport(Darwin)
    /// Indicates that opening the file
    /// opens symbolic links instead of following them.
    ///
    /// If you specify this option
    /// and the file path you pass to
    /// <doc:FileDescriptor/open(_:_:options:permissions:retryOnInterrupt:)-2266j>
    /// is a symbolic link,
    /// then the link itself is opened instead of what it links to.
    ///
    /// The corresponding C constant is `O_SYMLINK`.
    @_alwaysEmitIntoClient
    public static var symlink: FileDescriptor.OpenOptions { .init(rawValue: _O_SYMLINK) }

    @_alwaysEmitIntoClient
    @available(*, unavailable, renamed: "symlink")
    public static var O_SYMLINK: FileDescriptor.OpenOptions { symlink }
#endif
}

final class SMB2FileHandle: @unchecked Sendable {
    private var client: SMB2Client
    private var handle: smb2fh?

    convenience init(forReadingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, .readOnly, on: client)
    }

    convenience init(forUpdatingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, .readWrite, options: [.append] , on: client)
    }

    convenience init(forOverwritingOrCreatingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, .writeOnly, options: [.create, .truncate], on: client)
    }

    convenience init(forOutputAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, .writeOnly, options: [.create], on: client)
    }
    
    convenience init(forCreatingIfNotExistsAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, .readWrite, options: [.create, .exclusiveCreate], on: client)
    }

    convenience init(
        path: String,
        opLock: OpLock = .none,
        impersonation: ImpersonationLevel = .impersonation,
        desiredAccess: Access = [.read, .write, .synchronize],
        fileAttributes: Attributes = [],
        shareAccess: ShareAccess = [.read, .write],
        createDisposition: CreateDisposition,
        createOptions: CreateOptions = [], on client: SMB2Client
    ) throws {
        var leaseData = opLock.leaseContext.map { Data($0.regions.joined()) } ?? .init()
        defer { withExtendedLifetime(leaseData) {} }
        // Trim before the separator swap: a leading "/" used to become a
        // leading "\", which Samba's CREATE rejects with INVALID_PARAMETER.
        let (_, result) = try path.trimmedPath.replacingOccurrences(of: "/", with: "\\").withCString { path in
            try client.async_await_pdu(dataHandler: SMB2FileID.init) {
                context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
                var req = smb2_create_request()
                req.requested_oplock_level = opLock.lockLevel
                req.impersonation_level = impersonation.rawValue
                req.desired_access = desiredAccess.rawValue
                req.file_attributes = fileAttributes.rawValue
                req.share_access = shareAccess.rawValue
                req.create_disposition = createDisposition.rawValue
                req.create_options = createOptions.rawValue
                req.name = path
                leaseData.withUnsafeMutableBytes {
                    req.create_context = $0.count > 0 ? $0.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil
                    req.create_context_length = UInt32($0.count)
                }
                return smb2_cmd_create_async(context, &req, SMB2Client.generic_handler, cbPtr)
            }
        }
        try self.init(fileDescriptor: result.rawValue, on: client)
    }
    
    convenience init(
        path: String, _ mode: FileDescriptor.AccessMode,
        options: FileDescriptor.OpenOptions = .init(),
        lock: OpLock = .none,
        on client: SMB2Client
    ) throws {
        try self.init(
            path: path,
            opLock: lock,
            desiredAccess: .init(mode, options: options),
            shareAccess: .init(mode),
            createDisposition: .init(options: options),
            createOptions: .init(options: options),
            on: client
        )
    }

    init(fileDescriptor: smb2_file_id, on client: SMB2Client) throws {
        self.client = client
        var fileDescriptor = fileDescriptor
        self.handle = try client.withThreadSafeContext { context in
            try smb2_fh_from_file_id(context, &fileDescriptor).unwrap()
        }
    }

    // This initializer does not support O_SYMLINK.
    private init(
        _ path: String, _ mode: FileDescriptor.AccessMode,
        options: FileDescriptor.OpenOptions = .init(),
        lock: OpLock = .none,
        on client: SMB2Client
    ) throws {
        let (_, handle) = try client.async_await(dataHandler: OpaquePointer.init) {
            context, cbPtr -> Int32 in
            let flags = mode.rawValue | options.rawValue
            var leaseKey = lock.leaseContext.map { Data(value: $0.key) } ?? Data()
            return leaseKey.withUnsafeMutableBytes {
                smb2_open_async_with_oplock_or_lease(
                    context, path.trimmedPath, flags,
                    lock.lockLevel, lock.leaseState.rawValue,
                    !$0.isEmpty ? $0.baseAddress : nil,
                    SMB2Client.generic_handler, cbPtr
                )
            }
        }
        self.client = client
        self.handle = handle
    }

    deinit {
        // No network I/O here (close can block up to the timeout on the
        // releasing thread); the handle stays tracked and is freed by the
        // client's destroy sweep if it is never closed explicitly.
        handle = nil
    }

    var fileId: UUID {
        .init(uuid: (try? smb2_get_file_id(handle.unwrap()).unwrap().pointee) ?? compound_file_id)
    }

    func close() throws {
        guard let handle = handle else { return }
        self.handle = nil
        // Keep close on the same async_await lifecycle as every other op; the sync
        // smb2_close() wrapper would run its own poll loop while we hold the context lock.
        _ = try? client.async_await { context, cbPtr -> Int32 in
            smb2_close_async(context, handle, SMB2Client.generic_handler, cbPtr)
        }
    }

    func fstat() throws -> smb2_stat_64 {
        // The C compound is safe since the fork's pending-refcount fix: any
        // reply order completes exactly once, and a late attribute-tag reply
        // is applied at completion, so the file type is always final.
        var st = smb2_stat_64()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_fstat_async(context, try handle.unwrap(), &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }
    
    func setInfo<T>(_ value: T, type: InfoType = .file, infoClass: InfoClass) throws {
        // Fail fast like every other method: after close, fileId resolves to
        // the all-F compound placeholder and this used to still send a
        // SET_INFO round trip the server could only reject.
        _ = try handle.unwrap()
        try client.async_await_pdu(dataHandler: EmptyReply.init) {
            context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
            var value = value
            return withUnsafeMutablePointer(to: &value) { buf in
                var req = smb2_set_info_request()
                req.file_id = fileId.uuid
                req.info_type = type.rawValue
                req.file_info_class = infoClass.rawValue
                req.input_data = .init(buf)
                return smb2_cmd_set_info_async(context, &req, SMB2Client.generic_handler, cbPtr)
            }
        }
    }
    
    func set(stat: smb2_stat_64, attributes: Attributes) throws {
        // time_t is 32-bit on arm64_32: clamp instead of trapping for dates
        // beyond 2038 there (no-op on 64-bit platforms).
        func timeval(seconds: UInt64, nanoseconds: UInt64) -> smb2_timeval {
            smb2_timeval(
                tv_sec: time_t(clamping: Int64(bitPattern: seconds)),
                tv_usec: .init(nanoseconds / 1000)
            )
        }
        let bfi = smb2_file_basic_info(
            creation_time: timeval(seconds: stat.smb2_btime, nanoseconds: stat.smb2_btime_nsec),
            last_access_time: timeval(seconds: stat.smb2_atime, nanoseconds: stat.smb2_atime_nsec),
            last_write_time: timeval(seconds: stat.smb2_mtime, nanoseconds: stat.smb2_mtime_nsec),
            change_time: timeval(seconds: stat.smb2_ctime, nanoseconds: stat.smb2_ctime_nsec),
            file_attributes: attributes.rawValue,
            // Raw FILETIME fields are decode-only; the encoder reads the timevals.
            creation_time_raw: 0,
            last_access_time_raw: 0,
            last_write_time_raw: 0,
            change_time_raw: 0
        )
        try setInfo(bfi, infoClass: .basic)
    }

    func resize(to newSize: UInt64) throws {
        let handle = try handle.unwrap()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_ftruncate_async(context, handle, newSize, SMB2Client.generic_handler, cbPtr)
        }
    }

    var maxReadSize: Int {
        // 0 fallback (destroyed context) instead of -1: callers allocate buffers
        // from this value and a negative count would trap.
        max(0, (try? Int(client.withThreadSafeContext(smb2_get_max_read_size))) ?? 0)
    }

    /// This value allows softer streaming
    var optimizedReadSize: Int {
        maxReadSize
    }

    @discardableResult
    func seek(offset: Int64, from whence: FileDescriptor.SeekOrigin) throws -> Int64 {
        let handle = try handle.unwrap()
        return try client.withThreadSafeContext { context in
            let result = smb2_lseek(context, handle, offset, whence.rawValue, nil)
            try POSIXError.throwIfError(result, description: client.errorString)
            return result
        }
    }

    func read(length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : max(1, optimizedReadSize)
        var buffer = Data(repeating: 0, count: count)
        let result = try buffer.withUnsafeMutableBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_read_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), SMB2Client.generic_handler, cbPtr
                )
            }
        }
        return Data(buffer.prefix(Int(result)))
    }

    func read(toAbsoluteOffset offset: UInt64, length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : max(1, optimizedReadSize)
        var buffer = Data(repeating: 0, count: count)
        let result = try buffer.withUnsafeMutableBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_pread_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), offset, SMB2Client.generic_handler,
                    cbPtr
                )
            }
        }
        return buffer.prefix(Int(result))
    }

    var maxWriteSize: Int {
        max(0, (try? Int(client.withThreadSafeContext(smb2_get_max_write_size))) ?? 0)
    }

    var optimizedWriteSize: Int {
        maxWriteSize
    }

    func write<DataType: DataProtocol>(data: DataType) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        // Loop over short writes: libsmb2 caps each Write at the negotiated
        // size and reports the accepted count.
        var written = 0
        try Data(data).withUnsafeBytes { buffer in
            while written < buffer.count {
                let base = buffer.baseAddress!.advanced(by: written)
                let result = try client.async_await { context, cbPtr -> Int32 in
                    smb2_write_async(
                        context, handle, base, .init(buffer.count - written),
                        SMB2Client.generic_handler, cbPtr
                    )
                }
                // A server that accepts a non-empty Write but reports zero
                // bytes written would spin this loop forever (each round
                // trip satisfies the timeout); treat it as an error.
                guard result > 0 else {
                    throw POSIXError(.ioError, description: "Server reported zero bytes written.")
                }
                written += Int(result)
            }
        }
        return written
    }

    func write<DataType: DataProtocol>(toAbsoluteOffset offset: UInt64, data: DataType) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        var written = 0
        try Data(data).withUnsafeBytes { buffer in
            while written < buffer.count {
                guard offset <= UInt64.max - UInt64(written) else {
                    throw POSIXError(.invalidArgument, description: "Write offset overflows.")
                }
                let base = buffer.baseAddress!.advanced(by: written)
                let result = try client.async_await { context, cbPtr -> Int32 in
                    smb2_pwrite_async(
                        context, handle, base, .init(buffer.count - written),
                        offset + UInt64(written), SMB2Client.generic_handler, cbPtr
                    )
                }
                guard result > 0 else {
                    throw POSIXError(.ioError, description: "Server reported zero bytes written.")
                }
                written += Int(result)
            }
        }
        return written
    }

    func fsync() throws {
        let handle = try handle.unwrap()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_fsync_async(context, handle, SMB2Client.generic_handler, cbPtr)
        }
    }

    /// Requests an SMB2 server-side-copy resume key for this open file.
    func requestResumeKey() throws -> smb2_srv_copychunk_resume_key {
        let (_, key) = try client.async_await(
            dataHandler: { client, ptr -> smb2_srv_copychunk_resume_key in
                let key = try ptr.unwrap()
                    .assumingMemoryBound(to: smb2_srv_copychunk_resume_key.self).pointee
                try client.withThreadSafeContext { smb2_free_data($0, ptr) }
                return key
            }
        ) { [handle] context, cbPtr -> Int32 in
            guard let handle else { return -Int32(POSIXErrorCode.EIO.rawValue) }
            return smb2_request_resume_key_async(context, handle, SMB2Client.generic_handler, cbPtr)
        }
        return key
    }

    /// Issues one FSCTL_SRV_COPYCHUNK request. The C side encodes the key and
    /// chunks into the PDU synchronously, so pointer scopes only wrap the call.
    func copyChunks(_ chunks: [smb2_srv_copychunk], resumeKey: smb2_srv_copychunk_resume_key) throws {
        _ = try withUnsafePointer(to: resumeKey) { keyPtr in
            try chunks.withUnsafeBufferPointer { buffer in
                try client.async_await(dataHandler: { client, ptr in
                    try client.withThreadSafeContext { smb2_free_data($0, ptr) }
                }) { [handle] context, cbPtr -> Int32 in
                    guard let handle else { return -Int32(POSIXErrorCode.EIO.rawValue) }
                    return smb2_copychunk_async(
                        context, UInt32(SMB2_FSCTL_SRV_COPYCHUNK), keyPtr, handle,
                        buffer.baseAddress, UInt32(chunks.count),
                        SMB2Client.generic_handler, cbPtr
                    )
                }
            }
        }
    }
    
    
    func changeNotify(for type: SMB2FileChangeType) throws -> [SMB2FileChangeInfo] {
        let handle = try handle.unwrap()
        let (_, result) = try client.async_await(dataHandler: [SMB2FileChangeInfo].init) { context, dataPtr in
            smb2_notify_change_filehandle_async(
                context, handle,
                UInt16(type.contains([.recursive]) ? SMB2_CHANGE_NOTIFY_WATCH_TREE : 0),
                type.completionFilter,
                0,
                SMB2Client.generic_handler,
                dataPtr
            )
        }
        return result
    }

    @discardableResult
    func fcntl<DataType: DataProtocol, R: DecodableResponse>(
        command: IOCtl.Command, args: DataType = Data()
    ) throws -> R {
        defer { withExtendedLifetime(args) {} }
        var inputBuffer = [UInt8](args)
        return try inputBuffer.withUnsafeMutableBytes { buf in
            // max_output_response is clamped like the C wrappers do, so
            // SMB 2.0.2 servers with a small MaxTransactSize do not reject
            // the request outright.
            let maxOutputResponse = UInt32(
                max(0, min(65_535, client.maximumTransactionSize - 8 - buf.count))
            )
            return try client.async_await_pdu(dataHandler: R.init) { [handle] context, cbPtr
                -> UnsafeMutablePointer<smb2_pdu>? in
                // file_id is resolved here, under the context lock: the
                // teardown sweep frees closed file handles, so touching the
                // handle outside the lock races a concurrent disconnect.
                var req = smb2_ioctl_request(
                    ctl_code: command.rawValue,
                    file_id: smb2_get_file_id(try handle.unwrap()).pointee,
                    input_offset: 0, input_count: .init(buf.count),
                    max_input_response: 0,
                    output_offset: 0, output_count: UInt32(client.maximumTransactionSize),
                    max_output_response: maxOutputResponse,
                    flags: .init(SMB2_0_IOCTL_IS_FSCTL),
                    input: buf.baseAddress
                )
                return smb2_cmd_ioctl_async(context, &req, SMB2Client.generic_handler, cbPtr)
            }.data
        }
    }
    
    func fcntl<DataType: DataProtocol>(command: IOCtl.Command, args: DataType = Data()) throws {
        let _: AnyDecodableResponse = try fcntl(command: command, args: args)
    }
}

extension SMB2FileHandle {

    
    struct Attributes: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        static let readonly = Self(rawValue: SMB2_FILE_ATTRIBUTE_READONLY)
        static let hidden = Self(rawValue: SMB2_FILE_ATTRIBUTE_HIDDEN)
        static let system = Self(rawValue: SMB2_FILE_ATTRIBUTE_SYSTEM)
        static let directory = Self(rawValue: SMB2_FILE_ATTRIBUTE_DIRECTORY)
        static let archive = Self(rawValue: SMB2_FILE_ATTRIBUTE_ARCHIVE)
        static let normal = Self(rawValue: SMB2_FILE_ATTRIBUTE_NORMAL)
        static let temporary = Self(rawValue: SMB2_FILE_ATTRIBUTE_TEMPORARY)
        static let sparseFile = Self(rawValue: SMB2_FILE_ATTRIBUTE_SPARSE_FILE)
        static let reparsePoint = Self(rawValue: SMB2_FILE_ATTRIBUTE_REPARSE_POINT)
        static let compressed = Self(rawValue: SMB2_FILE_ATTRIBUTE_COMPRESSED)
        static let offline = Self(rawValue: SMB2_FILE_ATTRIBUTE_OFFLINE)
        static let notContentIndexed = Self(rawValue: SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        static let encrypted = Self(rawValue: SMB2_FILE_ATTRIBUTE_ENCRYPTED)
        static let integrityStream = Self(rawValue: SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM)
        static let noScrubData = Self(rawValue: SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA)
    }
    
    struct LeaseState: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        static let none = Self(rawValue: SMB2_LEASE_NONE)
        static let readCaching = Self(rawValue: SMB2_LEASE_READ_CACHING)
        static let handleCaching = Self(rawValue: SMB2_LEASE_HANDLE_CACHING)
        static let writeCaching = Self(rawValue: SMB2_LEASE_WRITE_CACHING)
    }
    
    enum OpLock: Sendable {
        case none
        case ii
        case exclusive
        case batch
        case lease(state: LeaseState, key: UUID)
        
        var lockLevel: UInt8 {
            switch self {
            case .none:
                .init(SMB2_OPLOCK_LEVEL_NONE)
            case .ii:
                .init(SMB2_OPLOCK_LEVEL_II)
            case .exclusive:
                .init(SMB2_OPLOCK_LEVEL_EXCLUSIVE)
            case .batch:
                .init(SMB2_OPLOCK_LEVEL_BATCH)
            case .lease:
                .init(SMB2_OPLOCK_LEVEL_LEASE)
            }
        }
        
        var leaseState: LeaseState {
            switch self {
            case .lease(let state, _):
                state
            default:
                .none
            }
        }
        
        var leaseContext: CreateLeaseContext? {
            switch self {
            case .lease(let state, let key):
                .init(state: state, key: key)
            default:
                nil
            }
        }
    }
    
    struct ImpersonationLevel: RawRepresentable, Hashable, Sendable {
        var rawValue: UInt32
        
        static let anonymous = Self(rawValue: SMB2_IMPERSONATION_ANONYMOUS)
        static let identification = Self(rawValue: SMB2_IMPERSONATION_IDENTIFICATION)
        static let impersonation = Self(rawValue: SMB2_IMPERSONATION_IMPERSONATION)
        static let delegate = Self(rawValue: SMB2_IMPERSONATION_DELEGATE)
    }
    
    struct Access: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(_ mode: FileDescriptor.AccessMode, options: FileDescriptor.OpenOptions) {
            switch mode {
            case .readWrite:
                self = [.read, .write, .delete]
            case .writeOnly:
                self = [.write, .delete]
            default:
                self = [.read]
            }
            if options.contains(.sync) {
                insert(.synchronize)
            }
        }
        
        /* Access mask common to all objects */
        static let fileReadEA = Self(rawValue: SMB2_FILE_READ_EA)
        static let fileWriteEA = Self(rawValue: SMB2_FILE_WRITE_EA)
        static let fileDeleteChild = Self(rawValue: SMB2_FILE_DELETE_CHILD)
        static let fileReadAttributes = Self(rawValue: SMB2_FILE_READ_ATTRIBUTES)
        static let fileWriteAttributes = Self(rawValue: SMB2_FILE_WRITE_ATTRIBUTES)
        static let delete = Self(rawValue: SMB2_DELETE)
        static let readControl = Self(rawValue: SMB2_READ_CONTROL)
        static let writeDACL = Self(rawValue: SMB2_WRITE_DACL)
        static let writeOwner = Self(rawValue: SMB2_WRITE_OWNER)
        static let synchronize = Self(rawValue: SMB2_SYNCHRONIZE)
        static let acessSystemSecurity = Self(rawValue: SMB2_ACCESS_SYSTEM_SECURITY)
        static let maximumAllowed = Self(rawValue: SMB2_MAXIMUM_ALLOWED)
        static let genericAll = Self(rawValue: SMB2_GENERIC_ALL)
        static let genericExecute = Self(rawValue: SMB2_GENERIC_EXECUTE)
        static let genericWrite = Self(rawValue: SMB2_GENERIC_WRITE)
        static let genericRead = Self(rawValue: SMB2_GENERIC_READ)
        
        /* Access mask unique for file/pipe/printer */
        static let readData = Self(rawValue: SMB2_FILE_READ_DATA)
        static let writeData = Self(rawValue: SMB2_FILE_WRITE_DATA)
        static let appendData = Self(rawValue: SMB2_FILE_APPEND_DATA)
        static let execute = Self(rawValue: SMB2_FILE_EXECUTE)
        
        /* Access mask unique for directories */
        static let listDirectory = Self(rawValue: SMB2_FILE_LIST_DIRECTORY)
        static let addFile = Self(rawValue: SMB2_FILE_ADD_FILE)
        static let addSubdirectory = Self(rawValue: SMB2_FILE_ADD_SUBDIRECTORY)
        static let traverse = Self(rawValue: SMB2_FILE_TRAVERSE)
        
        static let read: Access = [.readData, .readAttributes]
        static let write: Access = [.writeData, .appendData, .fileWriteAttributes, .fileWriteEA, .readControl]
        static let executeList: Access = [.execute, .readAttributes]
        
        private static let readAttributes: Access = [.fileReadAttributes, .fileReadEA, .readControl]
    }
    
    struct ShareAccess: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(_ mode: FileDescriptor.AccessMode) {
            switch mode {
            case .readWrite:
                self = [.read, .write]
            case .writeOnly:
                self = [.write]
            default:
                self = [.read]
            }
        }
        
        static let read = Self(rawValue: SMB2_FILE_SHARE_READ)
        static let write = Self(rawValue: SMB2_FILE_SHARE_WRITE)
        static let delete = Self(rawValue: SMB2_FILE_SHARE_DELETE)
    }
    
    struct CreateDisposition: RawRepresentable, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(options: FileDescriptor.OpenOptions) {
            if options.contains(.create) {
                if options.contains(.exclusiveCreate) {
                    self = .create
                } else if options.contains(.truncate) {
                    self = .overwriteIfExists
                } else {
                    self = .openIfExists
                }
            } else {
                if options.contains(.truncate) {
                    self = .overwrite
                } else {
                    self = .open
                }
            }
        }
        
        /// If the file already exists, supersede it. Otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let supersede = Self(rawValue: SMB2_FILE_SUPERSEDE)
        
        /// If the file already exists, return success; otherwise, fail the operation.
        /// MUST NOT be used for a printer object.
        static let open = Self(rawValue: SMB2_FILE_OPEN)
        
        /// If the file already exists, fail the operation; otherwise, create the file.
        static let create = Self(rawValue: SMB2_FILE_CREATE)
        
        /// Open the file if it already exists; otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let openIfExists = Self(rawValue: SMB2_FILE_OPEN_IF)
        
        /// Overwrite the file if it already exists; otherwise, fail the operation.
        /// MUST NOT be used for a printer object.
        static let overwrite = Self(rawValue: SMB2_FILE_OVERWRITE)
        
        /// Overwrite the file if it already exists; otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let overwriteIfExists = Self(rawValue: SMB2_FILE_OVERWRITE_IF)
    }
    
    struct CreateOptions: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(options: FileDescriptor.OpenOptions) {
            self = []
            if options.contains(.directory) {
                insert(.directoryFile)
            }
            // FILE_NO_INTERMEDIATE_BUFFERING is invalid on directories
            // per MS-FSCC §2.1.5.1; Windows enforces this strictly and
            // rejects the CREATE with STATUS_INVALID_PARAMETER when
            // both FILE_DIRECTORY_FILE and FILE_NO_INTERMEDIATE_BUFFERING
            // are present on the same open. Suppress the buffering flag
            // when O_DIRECTORY is also set so callers don't have to
            // remember the constraint at every directory open site.
            if options.contains(.sync) && !options.contains(.directory) {
                insert(.noIntermediateBuffering)
            }
            if options.contains(.symlink) {
                insert(.openReparsePoint)
            }
        }
        
        static let directoryFile = Self(rawValue: SMB2_FILE_DIRECTORY_FILE)
        static let writeThrough = Self(rawValue: SMB2_FILE_WRITE_THROUGH)
        static let sequentialOnly = Self(rawValue: SMB2_FILE_SEQUENTIAL_ONLY)
        static let noIntermediateBuffering = Self(rawValue: SMB2_FILE_NO_INTERMEDIATE_BUFFERING)
        static let synchronousIOAlert = Self(rawValue: SMB2_FILE_SYNCHRONOUS_IO_ALERT)
        static let synchronousIONonAlert = Self(rawValue: SMB2_FILE_SYNCHRONOUS_IO_NONALERT)
        static let nonDirectoryFile = Self(rawValue: SMB2_FILE_NON_DIRECTORY_FILE)
        static let completeIfOplocked = Self(rawValue: SMB2_FILE_COMPLETE_IF_OPLOCKED)
        static let noEAKnowledge = Self(rawValue: SMB2_FILE_NO_EA_KNOWLEDGE)
        static let randomAccess = Self(rawValue: SMB2_FILE_RANDOM_ACCESS)
        static let deleteOnClose = Self(rawValue: SMB2_FILE_DELETE_ON_CLOSE)
        static let openByFileID = Self(rawValue: SMB2_FILE_OPEN_BY_FILE_ID)
        static let openForBackupIntent = Self(rawValue: SMB2_FILE_OPEN_FOR_BACKUP_INTENT)
        static let noCompression = Self(rawValue: SMB2_FILE_NO_COMPRESSION)
        static let openRemoteInstance = Self(rawValue: SMB2_FILE_OPEN_REMOTE_INSTANCE)
        static let openRequiringOplock = Self(rawValue: SMB2_FILE_OPEN_REQUIRING_OPLOCK)
        static let disallowExclusive = Self(rawValue: SMB2_FILE_DISALLOW_EXCLUSIVE)
        static let reserveOpfilter = Self(rawValue: SMB2_FILE_RESERVE_OPFILTER)
        static let openReparsePoint = Self(rawValue: SMB2_FILE_OPEN_REPARSE_POINT)
        static let openNoRecall = Self(rawValue: SMB2_FILE_OPEN_NO_RECALL)
        static let openForFreeSpaceQuery = Self(rawValue: SMB2_FILE_OPEN_FOR_FREE_SPACE_QUERY)
    }
    
    struct CreateLeaseContext: EncodableArgument {
        typealias Element = UInt8

        private static let headerLength = 24

        /// The create-context name is defined in network byte order
        /// ([MS-SMB2] 2.2.13.2), unlike every other SMB2 integer field.
        private static let name: [UInt8] = [0x52, 0x71, 0x4c, 0x73] // "RqLs"

        var state: LeaseState
        var key: UUID
        var parentKey: UUID?

        var regions: [Data] {
            // Without a parent key this is a plain V1 lease context
            // (DataLength 32); with one it is the V2 form (DataLength 52) —
            // the two share the "RqLs" name and are told apart only by
            // DataLength. V1 requires LeaseFlags to be 0.
            let isV2 = parentKey != nil
            let dataLength: UInt32 = isV2 ? 52 : UInt32(SMB2_CREATE_REQUEST_LEASE_SIZE)
            return [
                .init(value: 0 as UInt32), // chain offset
                .init(value: 16 as UInt16), // name offset
                .init(value: 4 as UInt16), // name length
                .init(value: 0 as UInt16), // reserved
                .init(value: UInt16(Self.headerLength)), // data offset
                .init(value: dataLength),
                .init(Self.name),
                .init(value: 0 as UInt32), // reserved
                .init(value: key),
                .init(value: state.rawValue),
                .init(value: isV2 ? 0x0000_0004 : 0 as UInt32), // LeaseFlags
                .init(value: 0 as UInt64), // LeaseDuration
            ] + (isV2 ? [
                .init(value: parentKey ?? .zero),
                .init(value: 4 as UInt16), // Epoch
                .init(value: 0 as UInt16), // Reserved
            ] : [])
        }

        init(state: LeaseState, key: UUID, parentKey: UUID? = nil) {
            self.state = state
            self.key = key
            self.parentKey = parentKey
        }
    }

    struct InfoType: RawRepresentable, Sendable {
        var rawValue: UInt8
        
        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        static let file = Self(rawValue: SMB2_0_INFO_FILE)
        static let fileSystem = Self(rawValue: SMB2_0_INFO_FILESYSTEM)
        static let security = Self(rawValue: SMB2_0_INFO_SECURITY)
        static let quota = Self(rawValue: SMB2_0_INFO_QUOTA)
    }
    
    struct InfoClass: RawRepresentable, Sendable {
        var rawValue: UInt8
        
        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        static let directory = Self(rawValue: SMB2_FILE_DIRECTORY_INFORMATION)
        static let fullDirectory = Self(rawValue: SMB2_FILE_FULL_DIRECTORY_INFORMATION)
        static let bothDirectory = Self(rawValue: SMB2_FILE_BOTH_DIRECTORY_INFORMATION)
        static let basic = Self(rawValue: SMB2_FILE_BASIC_INFORMATION)
        static let standard = Self(rawValue: SMB2_FILE_STANDARD_INFORMATION)
        static let `internal` = Self(rawValue: SMB2_FILE_INTERNAL_INFORMATION)
        static let extendedAttribute = Self(rawValue: SMB2_FILE_EA_INFORMATION)
        static let access = Self(rawValue: SMB2_FILE_ACCESS_INFORMATION)
        static let name = Self(rawValue: SMB2_FILE_NAME_INFORMATION)
        static let rename = Self(rawValue: SMB2_FILE_RENAME_INFORMATION)
        static let link = Self(rawValue: SMB2_FILE_LINK_INFORMATION)
        static let named = Self(rawValue: SMB2_FILE_NAMES_INFORMATION)
        static let disposition = Self(rawValue: SMB2_FILE_DISPOSITION_INFORMATION)
        static let position = Self(rawValue: SMB2_FILE_POSITION_INFORMATION)
        static let fullExtendedAttribute = Self(rawValue: SMB2_FILE_FULL_EA_INFORMATION)
        static let mode = Self(rawValue: SMB2_FILE_MODE_INFORMATION)
        static let alignment = Self(rawValue: SMB2_FILE_ALIGNMENT_INFORMATION)
        static let all = Self(rawValue: SMB2_FILE_ALL_INFORMATION)
        static let endOfFile = Self(rawValue: SMB2_FILE_END_OF_FILE_INFORMATION)
        static let alternativeName = Self(rawValue: SMB2_FILE_ALTERNATE_NAME_INFORMATION)
        static let objectID = Self(rawValue: SMB2_FILE_OBJECT_ID_INFORMATION)
        static let attributeTag = Self(rawValue: SMB2_FILE_ATTRIBUTE_TAG_INFORMATION)
        static let normalizedName = Self(rawValue: SMB2_FILE_NORMALIZED_NAME_INFORMATION)
        static let id = Self(rawValue: SMB2_FILE_ID_INFORMATION)
    }
}

extension RawRepresentable where RawValue == UInt32 {
    init(rawValue: Int32) {
        self.init(rawValue: .init(bitPattern: rawValue))!
    }
}

extension RawRepresentable where RawValue: BinaryInteger {
    init(rawValue: Int32) {
        self.init(rawValue: .init(truncatingIfNeeded: rawValue))!
    }
}

extension smb2_stat_64 {
    init(fileInfo info: smb2_file_all_info) {
        self.init()
        smb2_attributes = info.basic.file_attributes
        smb2_nlink = info.standard.number_of_links
        smb2_ino = info.index_number
        smb2_size = info.standard.end_of_file
        // time_t is signed while smb2_stat_64 stores seconds in uint64 fields.
        smb2_atime = UInt64(truncatingIfNeeded: info.basic.last_access_time.tv_sec)
        smb2_atime_nsec = UInt64(info.basic.last_access_time.tv_usec) * 1000
        smb2_mtime = UInt64(truncatingIfNeeded: info.basic.last_write_time.tv_sec)
        smb2_mtime_nsec = UInt64(info.basic.last_write_time.tv_usec) * 1000
        smb2_ctime = UInt64(truncatingIfNeeded: info.basic.change_time.tv_sec)
        smb2_ctime_nsec = UInt64(info.basic.change_time.tv_usec) * 1000
        smb2_btime = UInt64(truncatingIfNeeded: info.basic.creation_time.tv_sec)
        smb2_btime_nsec = UInt64(info.basic.creation_time.tv_usec) * 1000
        setResourceType(reparseTag: 0)
    }

    mutating func setResourceType(reparseTag: UInt32) {
        smb2_type = smb2_attributes & UInt32(SMB2_FILE_ATTRIBUTE_DIRECTORY) != 0
            ? UInt32(SMB2_TYPE_DIRECTORY) : UInt32(SMB2_TYPE_FILE)
        smb2_reparse_tag = 0
        guard smb2_attributes & UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT) != 0 else { return }
        smb2_reparse_tag = reparseTag

        // Match libsmb2's classification, including WSL special files and the
        // name-surrogate bit for tags that are not explicitly known.
        switch reparseTag {
        case 0, UInt32(SMB2_REPARSE_TAG_SYMLINK), UInt32(SMB2_REPARSE_TAG_MOUNT_POINT),
             UInt32(SMB2_REPARSE_TAG_LX_SYMLINK):
            smb2_type = UInt32(SMB2_TYPE_LINK)
        case UInt32(SMB2_REPARSE_TAG_LX_FIFO):
            smb2_type = UInt32(SMB2_TYPE_FIFO)
        case UInt32(SMB2_REPARSE_TAG_LX_CHR):
            smb2_type = UInt32(SMB2_TYPE_CHARDEV)
        case UInt32(SMB2_REPARSE_TAG_LX_BLK):
            smb2_type = UInt32(SMB2_TYPE_BLOCKDEV)
        case UInt32(SMB2_REPARSE_TAG_AF_UNIX):
            smb2_type = UInt32(SMB2_TYPE_SOCKET)
        default:
            if reparseTag & UInt32(SMB2_REPARSE_TAG_NAME_SURROGATE_BIT) != 0 {
                smb2_type = UInt32(SMB2_TYPE_LINK)
            }
        }
    }

    struct ResourceType: RawRepresentable, Hashable, Sendable {
        var rawValue: UInt32
        
        static let file = Self(rawValue: SMB2_TYPE_FILE)
        static let directory = Self(rawValue: SMB2_TYPE_DIRECTORY)
        static let link = Self(rawValue: SMB2_TYPE_LINK)
        
        var urlResourceType: URLFileResourceType {
            switch self {
            case .directory:
                .directory
            case .file:
                .regular
            case .link:
                .symbolicLink
            default:
                .unknown
            }
        }
    }
    
    var resourceType: ResourceType {
        .init(rawValue: smb2_type)
    }
    
    var isDirectory: Bool {
        resourceType == .directory
    }

    func populateResourceValue(_ dic: inout [URLResourceKey: any Sendable]) {
        dic.reserveCapacity(11 + dic.count)
        dic[.fileSizeKey] = NSNumber(value: smb2_size)
        dic[.linkCountKey] = NSNumber(value: smb2_nlink)
        dic[.documentIdentifierKey] = NSNumber(value: smb2_ino)
        dic[.fileResourceTypeKey] = resourceType.urlResourceType
        dic[.isDirectoryKey] = NSNumber(value: resourceType == .directory)
        dic[.isRegularFileKey] = NSNumber(value: resourceType == .file)
        dic[.isSymbolicLinkKey] = NSNumber(value: resourceType == .link)

        // NT timestamps decode into uint64 fields; bitPattern keeps the conversion
        // trap-free for any server-supplied value (defensive; malformed times
        // simply yield far-off dates).
        dic[.contentModificationDateKey] = Date(
            timespec(tv_sec: Int(clamping: Int64(bitPattern: smb2_mtime)), tv_nsec: Int(smb2_mtime_nsec))
        )
        dic[.attributeModificationDateKey] = Date(
            timespec(tv_sec: Int(clamping: Int64(bitPattern: smb2_ctime)), tv_nsec: Int(smb2_ctime_nsec))
        )
        dic[.contentAccessDateKey] = Date(
            timespec(tv_sec: Int(clamping: Int64(bitPattern: smb2_atime)), tv_nsec: Int(smb2_atime_nsec))
        )
        dic[.creationDateKey] = Date(
            timespec(tv_sec: Int(clamping: Int64(bitPattern: smb2_btime)), tv_nsec: Int(smb2_btime_nsec))
        )
    }
}

extension UUID {
    static let zero = UUID(uuid: uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
}
