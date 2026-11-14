//
//  AMSMB2.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
#if !canImport(Darwin)
import FoundationNetworking
#endif
import SMB2
#if canImport(System)
import System
#else
import SystemPackage
#endif

/// Implements SMB2 File operations.
///
/// Completion handlers and progress closures run on an internal concurrent
/// dispatch queue; dispatch to your own queue (e.g. the main queue) before
/// touching UI state.
#if canImport(Darwin)
@objc(AMSMB2Manager)
#endif
public class SMB2Manager: NSObject, NSSecureCoding, Codable, NSCopying, CustomReflectable, @unchecked Sendable {
    public typealias SimpleCompletionHandler = (@Sendable (_ error: (any Error)?) -> Void)?
    public typealias ReadProgressHandler = (@Sendable (_ bytes: Int64, _ total: Int64) -> Bool)?
    public typealias WriteProgressHandler = (@Sendable (_ bytes: Int64) -> Bool)?
    fileprivate typealias CopyProgressHandler = (@Sendable
        (_ bytes: Int64, _ soFar: Int64, _ total: Int64) -> Int64?)?

    private let clientLock = NSLock()
    private var _client: SMB2Client?
    private var _clientEncrypted = false

    fileprivate var client: SMB2Client? {
        get { clientState.client }
    }

    /// Connects must record the connection's encryption alongside it:
    /// `connectShare(name:encrypted:)` must not hand back a live
    /// connection negotiated with a different encryption mode.
    private func setClient(_ client: SMB2Client?, encrypted: Bool) {
        clientLock.lock()
        let previous = _client
        _client = client
        _clientEncrypted = encrypted
        clientLock.unlock()
        // Client destruction may acquire the context lock and perform I/O.
        withExtendedLifetime(previous) {}
    }

    private var clientState: (client: SMB2Client?, encrypted: Bool, timeout: TimeInterval) {
        clientLock.lock()
        defer { clientLock.unlock() }
        return (_client, _clientEncrypted, _timeout)
    }

    /// SMB2 Share URL.
    public let url: URL

    fileprivate let _domain: String
    fileprivate var _workstation: String
    fileprivate let _user: String
    fileprivate let _password: String
    fileprivate let q: DispatchQueue
    fileprivate var _timeout: TimeInterval

    fileprivate let connectLock = NSLock()
    fileprivate let operationLock = NSCondition()
    fileprivate var operationCount: Int = 0

    /// The timeout interval to use when doing an operation until getting response. Default value is 60 seconds.
    /// Set this to 0 or negative value in order to disable it.
    open var timeout: TimeInterval {
        get {
            // A destroyed context reads as 0 ("disabled"); fall back to the
            // configured value so encode/copy of a failed manager do not
            // round-trip into "timeouts disabled".
            let state = clientState
            if let client = state.client, client.isActive {
                return client.timeout
            }
            return state.timeout
        }
        set {
            // Non-finite/negative values are "disable", same as zero;
            // normalizing here keeps libsmb2 from stamping PDUs with
            // already-expired deadlines (its check is "non-zero", not
            // "positive"), and the clamp keeps Int32 conversion finite.
            let normalized = SMB2Manager.normalizedTimeout(newValue)
            clientLock.lock()
            _timeout = normalized
            let client = _client
            clientLock.unlock()
            client?.timeout = normalized
        }
    }

    static func normalizedTimeout(_ value: TimeInterval) -> TimeInterval {
        guard value.isFinite, value > 0 else { return 0 }
        return min(value.rounded(.up), TimeInterval(Int32.max))
    }

    override public var debugDescription: String {
        var result = ""
        for (label, value) in customMirror.children {
            result.append("\(label ?? ""): \(value) ")
        }
        return result
    }

    public var customMirror: Mirror {
        let state = clientState
        var c: [(label: String?, value: Any)] = []

        c.append((label: "url", value: url))
        c.append((label: "isConnected", value: (state.client?.isActive ?? false)))
        c.append((label: "timeout", value: state.timeout))
        if !_domain.isEmpty { c.append((label: "domain", value: _domain)) }
        if !_workstation.isEmpty { c.append((label: "workstation", value: _workstation)) }
        c.append((label: "user", value: _user))
        if let connectedShare = state.client?.share { c.append((label: "share", value: connectedShare)) }

        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }

    /**
     Initializes a SMB2 class with given url and credential.

     - Note: For now, only user/password credential on NTLM servers are supported.

     - Important: A connection to a share must be established by `connectShare(name:completionHandler:)` before any operation.

     - Parameters:
       - url: SMB server's URL.
       - domain: User's domain, if applicable
       - credential: Username and password.
     */
    public init?(url: URL, domain: String = "", credential: URLCredential?) {
        guard url.scheme?.lowercased() == "smb", url.host != nil else {
            return nil
        }
        let hostLabel = url.host.map { "_" + $0 } ?? ""
        self.q = DispatchQueue(
            label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent
        )
        self.url = url

        var domain = domain
        var workstation = ""
        var user = "guest"

        if var undigestedUser = credential?.user ?? url.user {
            // Extract domain
            if domain.isEmpty, undigestedUser.components(separatedBy: ";").count == 2 {
                let comps = undigestedUser.components(separatedBy: ";")
                domain = comps[0]
                undigestedUser = comps[1]
            }

            let userComps = undigestedUser.components(separatedBy: "\\")
            switch userComps.count {
            case 1:
                user = userComps[0]
            case 2:
                workstation = userComps[0]
                user = userComps[1]
            default:
                break
            }
        }

        self._domain = domain
        self._workstation = workstation
        self._user = user
        self._password = credential?.password ?? ""
        self._timeout = 60.0
        super.init()
    }

    public required init?(coder aDecoder: NSCoder) {
        guard let url = aDecoder.decodeObject(of: NSURL.self, forKey: CodingKeys.url.stringValue) as URL? else {
            aDecoder.failWithError(
                CocoaError(
                    .coderValueNotFound,
                    userInfo: [NSLocalizedDescriptionKey: "URL is not set."]
                )
            )
            return nil
        }
        guard url.scheme?.lowercased() == "smb", url.host != nil else {
            aDecoder.failWithError(
                CocoaError(
                    .coderReadCorrupt,
                    userInfo: [NSLocalizedDescriptionKey: "URL is not valid."]
                )
            )
            return nil
        }

        let hostLabel = url.host.map { "_" + $0 } ?? ""
        self.q = DispatchQueue(
            label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent
        )
        self.url = url
        self._domain = aDecoder.decodeObject(of: NSString.self, forKey: CodingKeys.domain.stringValue) as String? ?? ""
        self._workstation =
            aDecoder.decodeObject(of: NSString.self, forKey: CodingKeys.workstation.stringValue) as String? ?? ""
        self._user = aDecoder.decodeObject(of: NSString.self, forKey: CodingKeys.user.stringValue) as String? ?? "guest"
        self._password =
            aDecoder.decodeObject(of: NSString.self, forKey: CodingKeys.password.stringValue) as String? ?? ""
        // decodeDouble returns 0 for a missing key; 0 means "timeouts
        // disabled" here, so a stripped archive would hang every operation.
        if aDecoder.containsValue(forKey: CodingKeys.timeout.stringValue) {
            self._timeout = SMB2Manager.normalizedTimeout(
                aDecoder.decodeDouble(forKey: CodingKeys.timeout.stringValue)
            )
        } else {
            self._timeout = 60
        }
        super.init()
    }

    open func encode(with aCoder: NSCoder) {
        aCoder.encode(url, forKey: CodingKeys.url.stringValue)
        aCoder.encode(_domain, forKey: CodingKeys.domain.stringValue)
        aCoder.encode(_workstation, forKey: CodingKeys.workstation.stringValue)
        aCoder.encode(_user, forKey: CodingKeys.user.stringValue)
        aCoder.encode(_password, forKey: CodingKeys.password.stringValue)
        aCoder.encode(timeout, forKey: CodingKeys.timeout.stringValue)
    }

    public static var supportsSecureCoding: Bool {
        true
    }

    enum CodingKeys: String, CodingKey {
        case url, domain, workstation
        case user, password, timeout
    }

    public required init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let url = try container.decode(URL.self, forKey: .url)
        guard url.scheme?.lowercased() == "smb", url.host != nil else {
            throw DecodingError.dataCorruptedError(
                forKey: CodingKeys.url, in: container, debugDescription: "URL is not smb."
            )
        }

        let hostLabel = url.host.map { "_" + $0 } ?? ""
        self.q = DispatchQueue(
            label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent
        )
        self.url = url
        self._domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? ""
        self._workstation = try container.decodeIfPresent(String.self, forKey: .workstation) ?? ""
        self._user = try container.decodeIfPresent(String.self, forKey: .user) ?? ""
        self._password = try container.decodeIfPresent(String.self, forKey: .password) ?? ""
        self._timeout = SMB2Manager.normalizedTimeout(
            try container.decodeIfPresent(TimeInterval.self, forKey: .timeout) ?? 60
        )
        super.init()
    }

    open func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(url, forKey: .url)
        try container.encode(_domain, forKey: .domain)
        try container.encode(_workstation, forKey: .workstation)
        try container.encode(_user, forKey: .user)
        try container.encode(_password, forKey: .password)
        try container.encode(timeout, forKey: .timeout)
    }

    open func copy(with _: NSZone? = nil) -> Any {
        let new = SMB2Manager(
            url: url, domain: _domain,
            credential: URLCredential(user: _user, password: _password, persistence: .forSession)
        )!
        new._workstation = _workstation
        new.timeout = timeout
        return new
    }

    /**
     Connects to a share.

     - Parameters:
       - name: Share name to connect.
       - encrypted: Enables SMB3 encryption if `true`, it fails with error in case server does not support encryption.
       - completionHandler: closure will be run after enumerating is completed.
     */
    open func connectShare(
        name: String, encrypted: Bool = false, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) {
            self.connectLock.lock()
            defer { self.connectLock.unlock() }
            let state = self.clientState
            var client: SMB2Client
            if let current = state.client, current.isActive, current.share == name,
                state.encrypted == encrypted
            {
                client = current
            } else {
                client = try self.connect(shareName: name, encrypted: encrypted)
            }

            // Workaround disgraceful disconnect issue (e.g. server timeout)
            do {
                try client.echo()
            } catch {
                client = try self.connect(shareName: name, encrypted: encrypted)
            }
        }
    }

    /**
     Connects to a share.

     - Parameters:
       - name: Share name to connect.
       - encrypted: Enables SMB3 encryption if `true`, it fails with error in case server does not support encryption.
     */
    open func connectShare(name: String, encrypted: Bool = false) async throws {
        try await withCheckedThrowingContinuation { continuation in
            connectShare(
                name: name, encrypted: encrypted, completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Disconnects from a share.

     - Parameters:
       - gracefully: waits until all queued operations are done before disconnecting from server. Default value is `false`.
       - completionHandler: closure will be run after enumerating is completed.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    open func disconnectShare(
        gracefully: Bool = false, completionHandler: SimpleCompletionHandler = nil
    ) {
        q.async {
            do {
                // Wait for in-flight operations before taking connectLock: a queued
                // connectShare holds an operation count while waiting for this lock,
                // so taking connectLock first would deadlock the pair.
                if gracefully {
                    self.operationLock.lock()
                    while self.operationCount > 0 {
                        self.operationLock.wait()
                    }
                    self.operationLock.unlock()
                }
                self.connectLock.lock()
                defer { self.connectLock.unlock() }
                try self.client?.disconnect()
                self.setClient(nil, encrypted: false)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }

    /**
     Disconnects from a share.

     - Parameters:
       - gracefully: waits until all queued operations are done before disconnecting from server. Default value is `false`.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    open func disconnectShare(gracefully: Bool = false) async throws {
        try await withCheckedThrowingContinuation { continuation in
            disconnectShare(gracefully: gracefully, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Sends echo to server. Use it to prevent timeout or check connectivity.

     - Parameter completionHandler: closure will be run after echoing server is completed.
     */
    open func echo(completionHandler: SimpleCompletionHandler) {
        with(completionHandler: completionHandler) { client in
            try client.echo()
        }
    }

    /// Sends echo to server. Use it to prevent timeout or check connectivity.
    open func echo() async throws {
        try await withCheckedThrowingContinuation { continuation in
            echo(completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Enumerates shares' list on server.

     - Parameters:
       - enumerateHidden: enumerating special/administrative e.g. user directory in macOS or
           shares usually ends with `$`, e.g. `C$` or `admin$`.
       - completionHandler: closure will be run after enumerating is completed.
       - result: An array of shares' name and remark name. `name` element can be passed to `connectShare()` function.
           remark name is suitable for displaying shares to user, but it is sometimes empty.
     */
    open func listShares(
        enumerateHidden: Bool = false,
        completionHandler: @Sendable @escaping (_ result: Result<[(name: String, comment: String)], any Error>) -> Void
    ) {
        // Connecting to Interprocess Communication share
        with(shareName: "IPC$", encrypted: false, completionHandler: completionHandler) { client in
            try client.shareEnum().map(enumerateHidden: enumerateHidden)
        }
    }

    /**
     Enumerates shares' list on server.

     - Parameters:
       - enumerateHidden: enumerating special/administrative e.g. user directory in macOS or
           shares usually ends with `$`, e.g. `C$` or `admin$`.
       - completionHandler: closure will be run after enumerating is completed.
     - Returns: An array of shares' name and remark name. `name` element can be passed to `connectShare()` function.
           remark name is suitable for displaying shares to user, but it is sometimes empty.
     */
    open func listShares(enumerateHidden: Bool = false) async throws -> [(
        name: String, comment: String
    )] {
        try await withCheckedThrowingContinuation { continuation in
            listShares(
                enumerateHidden: enumerateHidden, completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Enumerates directory contents in the give path.

     - Parameters:
       - atPath: path of directory to be enumerated.
       - recursive: subdirectories will enumerated if `true`.
       - completionHandler: closure will be run after enumerating is completed.
       - result: An array of `[URLResourceKey: Any]` which holds files' attributes. file name is stored in `.nameKey`.
     */
    open func contentsOfDirectory(
        atPath path: String, recursive: Bool = false,
        completionHandler: @Sendable @escaping (_ result: Result<[[URLResourceKey: any Sendable]], any Error>) -> Void
    ) {
        with(completionHandler: completionHandler) { client in
            try self.listDirectory(client: client, path: path, recursive: recursive)
        }
    }

    /**
     Enumerates directory contents in the give path.

     - Parameters:
       - atPath: path of directory to be enumerated.
       - recursive: subdirectories will enumerated if `true`.
     - Returns: An array of `[URLResourceKey: Any]` which holds files' attributes. file name is stored in `.nameKey`.
     */
    open func contentsOfDirectory(atPath path: String, recursive: Bool = false) async throws
        -> [[URLResourceKey: Any]]
    {
        try await withCheckedThrowingContinuation { continuation in
            contentsOfDirectory(
                atPath: path, recursive: recursive, completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Returns a dictionary that describes the attributes of the mounted file system on which a given path resides.

     - Parameters:
       - forPath: Any pathname within the mounted file system.
       - completionHandler: closure will be run after fetching attributes is completed.
       - result: A dictionary object that describes the attributes of the mounted file system on which path resides.
           See _File-System Attribute Keys_ for a description of the keys available in the dictionary.
     */
    open func attributesOfFileSystem(
        forPath path: String,
        completionHandler: @Sendable @escaping (_ result: Result<[FileAttributeKey: any Sendable], any Error>) -> Void
    ) {
        with(completionHandler: completionHandler) { client in
            // This exactly matches implementation of Swift Foundation.
            let stat = try client.statvfs(path)
            var result = [FileAttributeKey: any Sendable]()
            let blockSize = UInt64(stat.f_bsize)
            // NSNumber allows to cast to any number type, but it is unsafe to cast to types with lower bitwidth
            result[.systemNumber] = NSNumber(value: stat.f_fsid)
            // A defective server can report f_bsize == 0 or absurd counts;
            // guard the divisions and multiplications (overflow would trap).
            if blockSize > 0,
                stat.f_blocks < UInt64.max / blockSize,
                stat.f_bavail < UInt64.max / blockSize
            {
                result[.systemSize] = NSNumber(value: blockSize * stat.f_blocks)
                result[.systemFreeSize] = NSNumber(value: blockSize * stat.f_bavail)
            }
            result[.systemNodes] = NSNumber(value: stat.f_files)
            result[.systemFreeNodes] = NSNumber(value: stat.f_ffree)
            return result
        }
    }

    /**
     Returns a dictionary that describes the attributes of the mounted file system on which a given path resides.

     - Parameters:
       - forPath: Any pathname within the mounted file system.
     - Returns: A dictionary object that describes the attributes of the mounted file system on which path resides.
           See _File-System Attribute Keys_ for a description of the keys available in the dictionary.
     */
    open func attributesOfFileSystem(forPath path: String) async throws -> [FileAttributeKey: Any] {
        try await withCheckedThrowingContinuation { continuation in
            attributesOfFileSystem(forPath: path, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Returns the attributes of the item at given path.

     - Parameters:
       - atPath: path of file to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - result: An dictionary with `URLResourceKey` as key which holds file's attributes.
     */
    open func attributesOfItem(
        atPath path: String,
        completionHandler: @Sendable @escaping (_ result: Result<[URLResourceKey: any Sendable], any Error>) -> Void
    ) {
        with(completionHandler: completionHandler) { client in
            let stat: smb2_stat_64
            do {
                stat = try client.stat(path)
            } catch POSIXError.ENOLINK {
                // `libsmb2` can not read symlink attributes using `stat`, so if we get
                // the related error, we simply open file as reparse point then use `fstat`.
                let file = try SMB2FileHandle(path: path, .readOnly, options: .symlink, on: client)
                stat = try file.fstat()
            }
            var result = [URLResourceKey: any Sendable]()
            let (_, fileName) = path.pathComponents
            let fullPath = path.trimmedPath
            result[.nameKey] = fileName
            result[.pathKey] = stat.isDirectory ? fullPath + "/" : fullPath
            stat.populateResourceValue(&result)
            return result
        }
    }

    /**
     Returns the attributes of the item at given path.

     - Parameters:
       - atPath: path of file to be enumerated.
     - Returns: An dictionary with `URLResourceKey` as key which holds file's attributes.
     */
    open func attributesOfItem(atPath path: String) async throws -> [URLResourceKey: any Sendable] {
        try await withCheckedThrowingContinuation { continuation in
            attributesOfItem(atPath: path, completionHandler: asyncHandler(continuation))
        }
    }
    
    /**
     Sets the attributes of the specified file or directory.
     
     - Parameters:
       - attributes: A dictionary containing as keys the attributes to set for path
            and as values the corresponding value for the attribute.
            You can set the following attributes: `creationDateKey`, `contentAccessDateKey`,
            `contentModificationDateKey`, `attributeModificationDateKey`,
            `isUserImmutableKey`, `isSystemImmutableKey` and `isHiddenKey`.
            You can change single attributes or any combination of attributes;
            you need not specify keys for all attributes.
       - path: The path of a file or directory.
       - completionHandler: closure will be run after operation is completed.
     */
    open func setAttributes(
        attributes: [URLResourceKey: Any],
        ofItemAtPath path: String,
        completionHandler: SimpleCompletionHandler
    ) {
        var stat = smb2_stat_64()
        var smb2Attributes = SMB2FileHandle.Attributes()
        do {
            for attribute in attributes {
                switch attribute.key {
                case .creationDateKey:
                    if let date = attributes.creationDate {
                        let timestamp = try SMB2Timestamp(date)
                        stat.smb2_btime = timestamp.seconds
                        stat.smb2_btime_nsec = timestamp.nanoseconds
                    }
                case .contentAccessDateKey:
                    if let date = attributes.contentAccessDate {
                        let timestamp = try SMB2Timestamp(date)
                        stat.smb2_atime = timestamp.seconds
                        stat.smb2_atime_nsec = timestamp.nanoseconds
                    }
                case .contentModificationDateKey:
                    if let date = attributes.contentModificationDate {
                        let timestamp = try SMB2Timestamp(date)
                        stat.smb2_mtime = timestamp.seconds
                        stat.smb2_mtime_nsec = timestamp.nanoseconds
                    }
                case .attributeModificationDateKey:
                    if let date = attributes.attributeModificationDate {
                        let timestamp = try SMB2Timestamp(date)
                        stat.smb2_ctime = timestamp.seconds
                        stat.smb2_ctime_nsec = timestamp.nanoseconds
                    }
                case .isUserImmutableKey:
                    guard let value = attribute.value as? Bool else { break }
                    smb2Attributes.insert(value ? .readonly : .normal)
                case .isSystemImmutableKey:
                    guard let value = attribute.value as? Bool else { break }
                    smb2Attributes.insert(value ? .system : .normal)
                case .isHiddenKey:
                    guard let value = attribute.value as? Bool else { break }
                    smb2Attributes.insert(value ? .hidden : .normal)
                default:
                    break
                }
            }
        } catch {
            completionHandler?(error)
            return
        }
        
        if smb2Attributes.subtracting(.normal) != [] {
            smb2Attributes.remove(.normal)
        }
        
        with(completionHandler: completionHandler) { [stat, smb2Attributes] client in
            let file = try SMB2FileHandle(forUpdatingAtPath: path, on: client)
            try file.set(stat: stat, attributes: smb2Attributes)
        }
    }
    
    /**
     Sets the attributes of the specified file or directory.
     
     - Parameters:
       - attributes: A dictionary containing as keys the attributes to set for path
            and as values the corresponding value for the attribute.
            You can set the following attributes: `creationDateKey`, `contentAccessDateKey`,
            `contentModificationDateKey`, `attributeModificationDateKey`, `isReadableKey`,
            `isUserImmutableKey`, `isSystemImmutableKey` and `isHiddenKey`.
            You can change single attributes or any combination of attributes;
            you need not specify keys for all attributes.
       - path: The path of a file or directory.
     */
    open func setAttributes(attributes: [URLResourceKey: Any], ofItemAtPath path: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            setAttributes(attributes: attributes, ofItemAtPath: path, completionHandler: asyncHandler(continuation))
        }
    }
    
    /**
     Creates a new symbolic link pointed to given destination.
     
     - Parameters:
       - path: The path of a file or directory.
       - destination:  Item that symbolic link will point to.
       - completionHandler: closure will be run after reading link is completed.
     */
    func createSymbolicLink(
        atPath path: String, withDestinationPath destination: String,
        completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try client.symlink(path, to: destination)
        }
    }

    /**
     Creates a new symbolic link pointed to given destination.

     - Parameters:
       - path: The path of a file or directory.
       - destination:  Item that symbolic link will point to.
     */
    func createSymbolicLink(atPath path: String, withDestinationPath destination: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            createSymbolicLink(atPath: path, withDestinationPath: destination, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Returns the path of the item pointed to by a symbolic link.

     - Parameters:
       - atPath: The path of a file or directory.
       - completionHandler: closure will be run after reading link is completed.
       - result: An String object containing the path of the directory or file to which the symbolic link path refers.
                 If the symbolic link is specified as a relative path, that relative path is returned.
     */
    open func destinationOfSymbolicLink(
        atPath path: String,
        completionHandler: @Sendable @escaping (_ result: Result<String, any Error>) -> Void
    ) {
        with(completionHandler: completionHandler) { client in
            try client.readlink(path)
        }
    }

    /**
     Returns the path of the item pointed to by a symbolic link.

     - Parameters:
       - atPath: The path of a file or directory.
     - Returns: An String object containing the path of the directory or file to which the symbolic link path refers.
                 If the symbolic link is specified as a relative path, that relative path is returned.
     */
    open func destinationOfSymbolicLink(atPath path: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            destinationOfSymbolicLink(atPath: path, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Creates a new directory at given path.

     - Parameters:
       - atPath: path of new directory to be created.
       - completionHandler: closure will be run after operation is completed.
     */
    open func createDirectory(atPath path: String, completionHandler: SimpleCompletionHandler) {
        with(completionHandler: completionHandler) { client in
            try client.mkdir(path)
        }
    }

    /**
     Creates a new directory at given path.

     - Parameters:
       - atPath: path of new directory to be created.
     */
    open func createDirectory(atPath path: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            createDirectory(atPath: path, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Removes an existing directory at given path.

     - Parameters:
       - atPath: path of directory to be removed.
       - recursive: children items will be deleted if `true`.
       - completionHandler: closure will be run after operation is completed.
     */
    open func removeDirectory(
        atPath path: String, recursive: Bool, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try self.removeDirectory(client: client, path: path, recursive: recursive)
        }
    }

    /**
     Removes an existing directory at given path.

     - Parameters:
       - atPath: path of directory to be removed.
       - recursive: children items will be deleted if `true`.
     - Returns: closure will be run after operation is completed.
     */
    open func removeDirectory(atPath path: String, recursive: Bool) async throws {
        try await withCheckedThrowingContinuation { continuation in
            removeDirectory(
                atPath: path, recursive: recursive, completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Removes an existing file at given path.

     - Parameters:
       - atPath: path of file to be removed.
       - completionHandler: closure will be run after operation is completed.
     */
    open func removeFile(atPath path: String, completionHandler: SimpleCompletionHandler) {
        with(completionHandler: completionHandler) { client in
            do {
                try client.unlink(path)
            } catch POSIXError.ENOLINK, POSIXError.ENETRESET {
                // Try to remove file as a symbolic link.
                try client.unlink(path, type: .link)
            }
        }
    }

    /**
     Removes an existing file at given path.

     - Parameters:
       - atPath: path of file to be removed.
     */
    open func removeFile(atPath path: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            removeFile(atPath: path, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Removes an existing file or directory at given path.

     - Parameters:
       - atPath: path of file or directory to be removed.
       - completionHandler: closure will be run after operation is completed.
     */
    open func removeItem(atPath path: String, completionHandler: SimpleCompletionHandler) {
        with(completionHandler: completionHandler) { client in
            let stat: smb2_stat_64
            do {
                stat = try client.stat(path)
            } catch POSIXError.ENOLINK {
                // `libsmb2` can not read symlink attributes using `stat`, so if we get
                // the related error, we simply open file as reparse point then use `fstat`.
                let file = try SMB2FileHandle(path: path, .readOnly, options: .symlink, on: client)
                stat = try file.fstat()
            }
            switch stat.resourceType {
            case .directory:
                try self.removeDirectory(client: client, path: path, recursive: true)
            case .file, .link:
                try client.unlink(path, type: stat.resourceType)
            default:
                // Special files (FIFO, socket, device reparse points) cannot
                // be deleted through the file interfaces; report it instead
                // of silently succeeding.
                throw POSIXError(
                    .notSupported,
                    description: "Removing this file type is not supported."
                )
            }
        }
    }

    /**
     Removes an existing file or directory at given path.

     - Parameters:
       - atPath: path of file or directory to be removed.
     */
    open func removeItem(atPath path: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            removeItem(atPath: path, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Truncates or extends the file represented by the path to a specified offset within the file and
     puts the file pointer at that position.

     If the file is extended (if offset is beyond the current end of file), the added characters are null bytes.

     - Parameters:
       - atPath: path of file to be truncated.
       - atOffset: final size of truncated file.
       - completionHandler: closure will be run after operation is completed.
     */
    open func truncateFile(
        atPath path: String, atOffset: UInt64, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try client.resize(path, to: atOffset)
        }
    }

    /**
     Truncates or extends the file represented by the path to a specified offset within the file and
     puts the file pointer at that position.

     If the file is extended (if offset is beyond the current end of file), the added characters are null bytes.

     - Parameters:
       - atPath: path of file to be truncated.
       - atOffset: final size of truncated file.
     */
    open func truncateFile(atPath path: String, atOffset: UInt64) async throws {
        try await withCheckedThrowingContinuation { continuation in
            truncateFile(
                atPath: path, atOffset: atOffset, completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Moves/Renames an existing file at given path to a new location.

     - Parameters:
       - atPath: path of file to be move.
       - toPath: new location of file.
       - completionHandler: closure will be run after operation is completed.
     */
    open func moveItem(
        atPath path: String, toPath: String, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try client.rename(path, to: toPath)
        }
    }

    /**
     Moves/Renames an existing file at given path to a new location.

     - Parameters:
       - atPath: path of file to be move.
       - toPath: new location of file.
     */
    open func moveItem(atPath path: String, toPath: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            moveItem(atPath: path, toPath: toPath, completionHandler: asyncHandler(continuation))
        }
    }

    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     per negotiated I/O chunk (64KiB to 8MiB).

     - Note: If range's lowerBound is bigger than file's size, an empty `Data` will be returned.
             If range's length exceeds file, returned data will be truncated to entire file content from given offset.

     - Parameters:
       - atPath: path of file to be fetched.
       - range: byte range that should be read, default value is whole file. e.g. `..<10` will read first ten bytes.
       - progress: reports progress of received bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - bytes: received bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
       - result: a `Data` object which contains file contents.
     */
    open func contents<R: RangeExpression>(
        atPath path: String, range: R? = Range<UInt64>?.none,
        progress: ReadProgressHandler,
        completionHandler: @Sendable @escaping (_ result: Result<Data, any Error>) -> Void
    ) where R.Bound: FixedWidthInteger {
        let range = range?.int64Range ?? 0..<Int64.max
        with(completionHandler: completionHandler) { client in
            guard !range.isEmpty else {
                return Data()
            }

            let stream = OutputStream.toMemory()
            try self.read(
                client: client, path: path, range: range, to: stream, progress: progress
            )
            return try (stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data).unwrap()
        }
    }

    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     per negotiated I/O chunk (64KiB to 8MiB).

     - Note: If range's lowerBound is bigger than file's size, an empty `Data` will be returned.
             If range's length exceeds file, returned data will be truncated to entire file content from given offset.

     - Parameters:
       - atPath: path of file to be fetched.
       - range: byte range that should be read, default value is whole file. e.g. `..<10` will read first ten bytes.
       - progress: reports progress of received bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - bytes: received bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
     - Returns: a `Data` object which contains file contents.
     */
    open func contents<R: RangeExpression>(
        atPath path: String, range: R? = Range<UInt64>?.none, progress: ReadProgressHandler = nil
    ) async throws -> Data where R.Bound: FixedWidthInteger {
        try await withCheckedThrowingContinuation { continuation in
            contents(
                atPath: path, range: range, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Streams data contents of a file from an offset with specified length. With reporting data and progress
     per negotiated I/O chunk (64KiB to 8MiB).

     - Parameters:
       - atPath: path of file to be fetched.
       - offset: first byte of file to be read, starting from zero.
       - fetchedData: returns data portion fetched and received bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - offset: offset of first byte of data portion in file.
       - total: expected content length.
       - data: data portion which read from server.
       - completionHandler: closure will be run after reading data is completed.
     */
    open func contents(
        atPath path: String, offset: Int64 = 0,
        fetchedData: @Sendable @escaping (_ offset: Int64, _ total: Int64, _ data: Data) -> Bool,
        completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            let file = try SMB2FileHandle(forReadingAtPath: path, on: client)
            let size = Int64(clamping: try file.fstat().smb2_size)

            var shouldContinue = true
            try file.seek(offset: offset, from: .start)
            while shouldContinue {
                let offset = try file.seek(offset: 0, from: .current)
                let data = try file.read()
                if data.isEmpty {
                    break
                }
                shouldContinue = fetchedData(offset, size, data)
            }
        }
    }

    // **DEPRECATED, DON'T USE**
    @available(swift, deprecated: 1)
    open func contents(
        atPath path: String, offset: Int64 = 0,
        fetchedData: @Sendable @escaping (_ offset: Int64, _ total: Int64, _ data: Data) -> Bool
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            contents(
                atPath: path, offset: offset, fetchedData: fetchedData,
                completionHandler: asyncHandler(continuation)
            )
        }
    }
    
    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     per negotiated I/O chunk (64KiB to 8MiB).

     - Note: If range's lowerBound is bigger than file's size, an empty `Data` will be returned.
             If range's length exceeds file, returned data will be truncated to entire file content from given offset.

     - Parameters:
       - atPath: path of file to be fetched.
       - range: byte range that should be read, default value is whole file. e.g. `..<10` will read first ten bytes.
     - Returns: an async stream of `Data` object which contains file contents.
     */
    @available(swift 5.9)
    open func contents<R: RangeExpression>(
        atPath path: String, range: R? = Range<UInt64>?.none
    ) -> AsyncThrowingStream<Data, any Error> where R.Bound: FixedWidthInteger {
        let range = range?.int64Range ?? 0..<Int64.max
        let (result, continuation) = AsyncThrowingStream<Data, any Error>.makeStream(bufferingPolicy: .unbounded)
        let consumerGone = StreamConsumerGone()
        continuation.onTermination = { _ in
            consumerGone.set()
        }

        queue { [client] in
            guard let client = client else {
                // Never leave the consumer awaiting a stream that cannot
                // produce anything.
                continuation.finish(
                    throwing: POSIXError(.socketNotConnected, description: nil)
                )
                return
            }
            var offset = range.lowerBound
            do {
                let file = try SMB2FileHandle(forReadingAtPath: path, on: client)
                try file.seek(offset: range.lowerBound, from: .start)
                while offset < range.upperBound, !consumerGone.isGone {
                    // Read optimal read size, or less if less is remaining.
                    let remainingLength = range.upperBound - offset
                    let optimizedReadSize = file.optimizedReadSize
                    let length = remainingLength < optimizedReadSize ? Int(remainingLength) : optimizedReadSize
                    let data = try file.read(length: length)
                    if data.isEmpty {
                        break
                    }
                    continuation.yield(data.prefix(Int(clamping: range.upperBound - offset)))
                    offset += Int64(data.count)
                }
                continuation.finish()
            } catch {
                continuation.finish(throwing: error)
            }
        }
        return result
    }
    
    /**
     Creates and writes data to file. With reporting progress per negotiated I/O chunk.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    open func write<DataType: DataProtocol>(
        data: DataType, toPath path: String, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        let data = Data(data)
        with(completionHandler: completionHandler) { client in
            try self.write(
                client: client, from: InputStream(data: data), toPath: path,
                progress: progress
            )
        }
    }

    /**
     Creates and writes data to file. With reporting progress per negotiated I/O chunk.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
     */
    open func write<DataType: DataProtocol>(
        data: DataType, toPath path: String, progress: WriteProgressHandler
    ) async throws {
        let data = Data(data)
        try await withCheckedThrowingContinuation { continuation in
            write(
                data: data, toPath: path, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }
    
    /**
     Appends data to an existing file at the given offset (the file is not created; use write(data:) for that). With reporting progress per negotiated I/O chunk.
     
     - Important: If file size is greater than offset, contents after offset shall be truncated.
         If file size is less than offset, file size will be increased to the offset first.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - offset: The offset that new data will be written to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    open func append<DataType: DataProtocol>(
        data: DataType, toPath path: String, offset: Int64, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        guard offset >= 0 else {
            completionHandler?(POSIXError(.invalidArgument, description: "Offset must not be negative."))
            return
        }
        let data = Data(data)
        with(completionHandler: completionHandler) { client in
            try self.write(
                client: client, from: InputStream(data: data), toPath: path,
                offset: offset, progress: progress
            )
        }
    }

    /**
     Appends data to an existing file at the given offset (the file is not created; use write(data:) for that). With reporting progress per negotiated I/O chunk.
     
     - Important: If file size is greater than offset, contents after offset shall be truncated.
         If file size is less than offset, file size will be increased to the offset first.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - offset: The offset that new data will be written to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
     */
    open func append<DataType: DataProtocol>(
        data: DataType, toPath path: String, offset: Int64, progress: WriteProgressHandler
    ) async throws {
        let data = Data(data)
        try await withCheckedThrowingContinuation { continuation in
            append(
                data: data, toPath: path, offset: offset, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Creates and writes input stream to file. With reporting progress per negotiated I/O chunk.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Important: Stream will be closed eventually if is not already opened when passed.

     - Parameters:
       - stream: input stream that provides data to be written to file.
       - toPath: path of file to be written.
       - chunkSize: chunk size to read from the stream. The default (0) picks the connection's negotiated optimal size.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    open func write<S>(
        stream: S, toPath path: String,
        chunkSize: Int = 0, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) where S: AsyncSequence & Sendable, S.Element: DataProtocol, S: SendableMetatype, S.Element: SendableMetatype, S.AsyncIterator: SendableMetatype {
        with(completionHandler: completionHandler) { client in
            try self.write(
                client: client, from: AsyncInputStream(stream: stream), toPath: path, chunkSize: chunkSize,
                progress: progress
            )
        }
    }

    /**
     Creates and writes input stream to file. With reporting progress per negotiated I/O chunk.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Important: Stream will be closed eventually if is not already opened when passed.

     - Parameters:
       - stream: input stream that provides data to be written to file.
       - toPath: path of file to be written.
       - chunkSize: chunk size to read from the stream. The default (0) picks the connection's negotiated optimal size.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
     */
    open func write<S>(
        stream: S, toPath path: String, progress: WriteProgressHandler
    ) async throws where S: AsyncSequence & Sendable, S.Element: DataProtocol, S: SendableMetatype, S.Element: SendableMetatype, S.AsyncIterator: SendableMetatype {
        try await withCheckedThrowingContinuation { continuation in
            write(
                stream: stream, toPath: path, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Copy file contents to a new location. With reporting progress per negotiated I/O chunk.

     - Note: This operation consists downloading and uploading file.

     - Parameters:
       - atPath: path of file to be copied from.
       - toPath: path of new file to be copied to.
       - recursive: copies directory structure and files if path is directory.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - bytes: written bytes count.
       - completionHandler: closure will be run after copying is completed.
     */
    @available(
        *, deprecated, message: "New method does server-side copy and is much faster.",
        renamed: "copyItem(atPath:toPath:recursive:progress:completionHandler:)"
    )
    open func copyContentsOfItem(
        atPath path: String, toPath: String, recursive: Bool,
        progress: ReadProgressHandler, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try self.recursiveCopyIterator(
                client: client, fromPath: path, toPath: toPath, recursive: recursive,
                progress: progress,
                handle: self.copyContentsOfFile(client:fromPath:toPath:progress:)
            )
        }
    }

    /**
     Copy files to a new location. With reporting progress per negotiated I/O chunk.

     - Parameters:
       - atPath: path of file to be copied from.
       - toPath: path of new file to be copied to.
       - recursive: copies directory structure and files if path is directory.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - bytes: written bytes count.
       - completionHandler: closure will be run after copying is completed.
     */
    open func copyItem(
        atPath path: String, toPath: String, recursive: Bool,
        progress: ReadProgressHandler, completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            try self.recursiveCopyIterator(
                client: client, fromPath: path, toPath: toPath, recursive: recursive,
                progress: progress,
                handle: self.copyFile(client:fromPath:toPath:progress:)
            )
        }
    }

    /**
     Copy files to a new location. With reporting progress per negotiated I/O chunk.

     - Parameters:
       - atPath: path of file to be copied from.
       - toPath: path of new file to be copied to.
       - recursive: copies directory structure and files if path is directory.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - bytes: written bytes count.
     */
    open func copyItem(
        atPath path: String, toPath: String, recursive: Bool, progress: ReadProgressHandler
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            copyItem(
                atPath: path, toPath: toPath, recursive: recursive, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Uploads local file contents to a new location. With reporting progress per negotiated I/O chunk.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of new file to be uploaded to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    open func uploadItem(
        at url: URL, toPath: String, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        uploadItem(
            at: url, toPath: toPath, overwrite: false, progress: progress,
            completionHandler: completionHandler
        )
    }

    /**
     Uploads local file contents to a location, optionally replacing an existing file. With reporting progress per negotiated I/O chunk.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of file to be uploaded to.
       - overwrite: if `true`, an existing file at `toPath` will be truncated and replaced.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    open func uploadItem(
        at url: URL, toPath: String, overwrite: Bool, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            guard try url.checkResourceIsReachable(), url.isFileURL,
                  let stream = InputStream(url: url)
            else {
                throw POSIXError(
                    .ioError,
                    description:
                    "Could not create Stream from given URL, or given URL is not a local file."
                )
            }

            try self.write(client: client, from: stream, toPath: toPath, overwrite: overwrite, progress: progress)
        }
    }

    /**
     Uploads local file contents to a new location. With reporting progress per negotiated I/O chunk.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of new file to be uploaded to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
     */
    open func uploadItem(
        at url: URL, toPath: String, progress: WriteProgressHandler
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            uploadItem(
                at: url, toPath: toPath, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Uploads local file contents to a location, optionally replacing an existing file. With reporting progress per negotiated I/O chunk.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of file to be uploaded to.
       - overwrite: if `true`, an existing file at `toPath` will be truncated and replaced.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
     */
    open func uploadItem(
        at url: URL, toPath: String, overwrite: Bool, progress: WriteProgressHandler
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            uploadItem(
                at: url, toPath: toPath, overwrite: overwrite, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }

    /**
     Downloads file contents to a local url. With reporting progress per negotiated I/O chunk.

     - Note: if a file already exists on given url, This function will overwrite to that url.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - atPath: path of file to be downloaded from.
       - at: url of a local file to be written to.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    open func downloadItem(
        atPath path: String, to url: URL, progress: ReadProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        with(completionHandler: completionHandler) { client in
            guard url.isFileURL, let stream = OutputStream(url: url, append: false) else {
                throw POSIXError(
                    .ioError,
                    description:
                    "Could not create Stream from given URL, or given URL is not a local file."
                )
            }
            try self.read(client: client, path: path, to: stream, progress: progress)
        }
    }

    /**
     Downloads file contents to a local url. With reporting progress per negotiated I/O chunk.

     - Note: if a file already exists on given url, This function will overwrite to that url.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - atPath: path of file to be downloaded from.
       - at: url of a local file to be written to.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
     */
    open func downloadItem(
        atPath path: String, to url: URL, progress: ReadProgressHandler
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            downloadItem(
                atPath: path, to: url, progress: progress,
                completionHandler: asyncHandler(continuation)
            )
        }
    }
    
    /// Monitor file/folder for changes and calls `completionHandler` when a change occurs.
    ///
    /// - Parameters:
    ///   - path: Path of file or folder to be monitored for changes.
    ///   - filter: Change types that will be monitored.
    ///   - completionHandler: closure will be run after a change in montored file/folder.
    func monitorItem(
        atPath path: String,
        for filter: SMB2FileChangeType,
        completionHandler: @Sendable @escaping (_ result: Result<[SMB2FileChangeInfo], any Error>) -> Void
    ) {
        with(completionHandler: completionHandler) { client in
            var options: FileDescriptor.OpenOptions = .sync
            switch try client.stat(path).resourceType {
            case .directory:
                options.insert(.directory)
            case .link:
                options.insert(.symlink)
            default:
                break
            }
            let file = try SMB2FileHandle(path: path, .readOnly, options: options, on: client)
            return try file.changeNotify(for: filter)
        }
    }
    
    /// Monitor file/folder for changes and returns when a change occurs.
    ///
    /// - Parameters:
    ///   - path: Path of file or folder to be monitored for changes.
    ///   - filter: Change types that will be monitored.
    @discardableResult
    func monitorItem(atPath path: String, for filter: SMB2FileChangeType) async throws -> [SMB2FileChangeInfo] {
        try await withCheckedThrowingContinuation { continuation in
            monitorItem(atPath: path, for: filter, completionHandler: asyncHandler(continuation))
        }
    }
}

extension SMB2Manager {
    private func queue(_ closure: @Sendable @escaping () -> Void) {
        operationLock.lock()
        operationCount += 1
        operationLock.unlock()
        q.async {
            closure()
            self.operationLock.lock()
            self.operationCount -= 1
            self.operationLock.broadcast()
            self.operationLock.unlock()
        }
    }

    private func initClient(_ client: SMB2Client, encrypted: Bool) {
        client.securityMode = [.enabled]
        client.authentication = .ntlmSsp
        // New contexts default to optional encryption. Setting seal to false now
        // disables negotiation entirely, including shares that require encryption.
        if encrypted {
            client.seal = true
        }

        client.domain = _domain
        client.workstation = _workstation
        client.user = _user
        client.password = _password
        client.timeout = clientState.timeout
    }

    private func connect(shareName: String, encrypted: Bool, publish: Bool = true) throws -> SMB2Client {
        let client = try SMB2Client()
        if publish {
            self.setClient(client, encrypted: encrypted)
        }
        initClient(client, encrypted: encrypted)
        // IPv6 literal hosts need their brackets back: url.host strips
        // them, and libsmb2 splits host:port on the first colon.
        let host = url.host!.contains(":") ? "[\(url.host!)]" : url.host!
        let server = host + (url.port.map { ":\($0)" } ?? "")
        try client.connect(server: server, share: shareName, user: _user)
        return client
    }

    private func with(
        completionHandler: SimpleCompletionHandler, handler: @Sendable @escaping () throws -> Void
    ) {
        queue {
            do {
                try handler()
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }

    private func with(
        completionHandler: SimpleCompletionHandler,
        handler: @Sendable @escaping (_ client: SMB2Client) throws -> Void
    ) {
        queue {
            do {
                try handler(self.client.unwrap())
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }

    private func with<T>(
        completionHandler: @Sendable @escaping (Result<T, any Error>) -> Void,
        handler: @Sendable @escaping (_ client: SMB2Client) throws -> T
    ) {
        queue {
            completionHandler(
                .init(catching: { () -> T in
                    try handler(self.client.unwrap())
                })
            )
        }
    }

    private func with<T>(
        shareName: String, encrypted: Bool, completionHandler: @Sendable @escaping (Result<T, any Error>) -> Void,
        handler: @Sendable @escaping (_ client: SMB2Client) throws -> T
    ) {
        queue {
            do {
                // An unpublished connection: the IPC$ client used for share
                // enumeration must not clobber (and tear down) whatever share
                // connection this manager is currently holding.
                let client = try self.connect(shareName: shareName, encrypted: encrypted, publish: false)
                defer { try? client.disconnect() }

                let result = try handler(client)
                completionHandler(.success(result))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
}

extension SMB2Manager {
    private func listDirectory(client: SMB2Client, path: String, recursive: Bool) throws
        -> [[URLResourceKey: any Sendable]]
    {
        var contents = [[URLResourceKey: any Sendable]]()
        let dir = try SMB2Directory(path.trimmedPath, on: client)
        for ent in dir {
            let name = ent.name
            if [".", ".."].contains(name) { continue }
            var result = [URLResourceKey: any Sendable]()
            result[.nameKey] = name
            result[.pathKey] = path.appendingPath(name, isDirectory: ent.st.isDirectory)
            ent.st.populateResourceValue(&result)
            contents.append(result)
        }

        if recursive {
            let subDirectories = contents.filter(\.isDirectory)

            for subDir in subDirectories {
                try contents.append(
                    contentsOf: listDirectory(
                        client: client, path: subDir.path.unwrap(), recursive: true
                    )
                )
            }
        }

        return contents
    }

    private func recursiveCopyIterator(
        client: SMB2Client, fromPath path: String, toPath: String, recursive: Bool,
        progress: ReadProgressHandler,
        handle: (
            _ client: SMB2Client, _ path: String, _ toPath: String,
            _ progress: CopyProgressHandler
        ) throws -> Int64?
    ) throws {
        let stat = try client.stat(path)
        if stat.isDirectory {
            try client.mkdir(toPath)

            let list = try listDirectory(client: client, path: path, recursive: recursive)
                .sortedByPath(.orderedAscending)
            let overallSize = list.overallSize

            var totalCopied: Int64 = 0
            for item in list {
                let itemPath = try item.path.unwrap()
                let destPath = itemPath.trimmedPath
                    .replacingOccurrences(of: path, with: toPath, options: .anchored)
                if item.isDirectory {
                    try client.mkdir(destPath)
                } else {
                    let bytes = try handle(
                        client, itemPath, destPath
                    ) { [totalCopied] bytes, soFar, _ -> Int64? in
                        if let progress {
                            return progress(totalCopied + soFar, overallSize) ? bytes : nil
                        } else {
                            return bytes
                        }
                    }
                    if let bytes {
                        totalCopied += bytes
                    } else {
                        break
                    }
                }
            }
        } else {
            _ = try handle(
                client, path, toPath
            ) { bytes, soFar, total -> Int64? in
                if let progress {
                    return progress(soFar, total) ? bytes : nil
                } else {
                    return bytes
                }
            }
        }
    }

    private func copyFile(
        client: SMB2Client, fromPath path: String, toPath: String, progress: CopyProgressHandler
    ) throws -> Int64? {
        let fileSource = try SMB2FileHandle(forReadingAtPath: path, on: client)
        let size = Int64(clamping: try fileSource.fstat().smb2_size)
        let sourceKey = try fileSource.requestResumeKey()
        // MS-SMB2 caps a single SRV_COPYCHUNK at 1 MiB regardless of the
        // negotiated write size.
        let chunkSize = min(max(1, fileSource.optimizedWriteSize), 1_048_576)
        let fileDest = try SMB2FileHandle(forCreatingIfNotExistsAtPath: toPath, on: client)
        var shouldContinue = true
        var offset: UInt64 = 0
        while offset < UInt64(size) {
            // Compute the per-chunk length in UInt64 before narrowing: converting
            // size itself to UInt32 traps for files larger than 4 GiB.
            let length = UInt32(min(UInt64(chunkSize), UInt64(size) - offset))
            try fileDest.copyChunks(
                [smb2_srv_copychunk(
                    source_offset: offset, target_offset: offset, length: length, reserved: 0
                )],
                resumeKey: sourceKey
            )
            if let progress {
                shouldContinue = progress(Int64(length), Int64(offset) + Int64(length), size) != nil
            }

            if !shouldContinue {
                break
            }
            offset += UInt64(length)
        }
        return shouldContinue ? size : nil
    }

    private func copyContentsOfFile(
        client: SMB2Client, fromPath path: String, toPath: String, progress: CopyProgressHandler
    ) throws -> Int64? {
        let fileRead = try SMB2FileHandle(forReadingAtPath: path, on: client)
        let size = Int64(clamping: try fileRead.fstat().smb2_size)
        let fileWrite = try SMB2FileHandle(forCreatingIfNotExistsAtPath: toPath, on: client)
        var shouldContinue = true
        var written = 0
        while shouldContinue {
            let data = try fileRead.read()
            written += try fileWrite.write(data: data)
            let offset = try fileRead.seek(offset: 0, from: .current)
            if let progress {
                shouldContinue = progress(Int64(written), offset, size) != nil
            }
            shouldContinue = shouldContinue && !data.isEmpty
        }
        try fileWrite.fsync()
        return shouldContinue ? Int64(written) : nil
    }

    private func removeDirectory(client: SMB2Client, path: String, recursive: Bool) throws {
        if recursive {
            // To delete directory recursively, first we list directory contents recursively,
            // Then sort path descending which will put child files before containing directory,
            // Then we will unlink/rmdir every entry.
            //
            // This block will only delete children of directory, the path itself will removed after if block.
            let list = try listDirectory(client: client, path: path, recursive: true)
                .sortedByPath(.orderedDescending)

            for item in list {
                let itemPath = try item.path.unwrap()
                if item.isDirectory {
                    try client.rmdir(itemPath)
                } else {
                    try client.unlink(itemPath)
                }
            }
        }

        try client.rmdir(path)
    }

    private func read(
        client: SMB2Client, path: String, range: Range<Int64> = 0..<Int64.max,
        to stream: OutputStream, progress: ReadProgressHandler
    ) throws {
        let file = try SMB2FileHandle(forReadingAtPath: path, on: client)
        let filesize = Int64(clamping: try file.fstat().smb2_size)
        // Both operands are non-negative here (int64Range clamps negative
        // lower bounds to 0), so the subtraction cannot overflow.
        let length = range.upperBound - range.lowerBound
        let size = min(length, filesize - range.lowerBound)

        try stream.withOpenStream {
            var shouldContinue = true
            var sent: Int64 = 0
            try file.seek(offset: range.lowerBound, from: .start)
            while shouldContinue {
                let prefCount = Int(min(Int64(file.optimizedReadSize), Int64(size - sent)))
                guard prefCount > 0 else {
                    break
                }

                let data = try file.read(length: prefCount)
                if data.isEmpty {
                    break
                }
                let written = try stream.write(data)
                guard written == data.count else {
                    throw POSIXError(
                        .ioError, description: "Inconsistency in reading from SMB file handle."
                    )
                }
                sent += Int64(written)
                shouldContinue = progress?(sent, size) ?? true
            }
        }
    }

    private func write(
        client: SMB2Client, from stream: InputStream, toPath: String,
        offset: Int64? = nil, overwrite: Bool = false, chunkSize: Int = 0, progress: WriteProgressHandler
    ) throws {
        let file: SMB2FileHandle
        if let offset {
            try client.resize(toPath, to: .init(offset))
            file = try SMB2FileHandle(forOutputAtPath: toPath, on: client)
            try file.seek(offset: offset, from: .start)
        } else if overwrite {
            file = try SMB2FileHandle(forOverwritingOrCreatingAtPath: toPath, on: client)
        } else {
            file = try SMB2FileHandle(forCreatingIfNotExistsAtPath: toPath, on: client)
        }
        // Cap the segment buffer: a chunk larger than the negotiated write
        // size would be allocated in full per segment while the server only
        // accepts negotiated-size writes anyway.
        let chunkSize = min(chunkSize > 0 ? chunkSize : max(1, file.optimizedWriteSize), 16 << 20)
        var totalWritten: UInt64 = 0

        try stream.withOpenStream {
            while true {
                let segment = try stream.readData(maxLength: chunkSize)
                if segment.isEmpty {
                    break
                }
                // Short writes are legal: libsmb2 caps each Write at the
                // negotiated size. Keep writing the remainder.
                var segmentOffset = 0
                while segmentOffset < segment.count {
                    let written = try file.write(
                        toAbsoluteOffset: UInt64(offset ?? 0) + totalWritten,
                        data: segment.dropFirst(segmentOffset)
                    )
                    segmentOffset += written
                    totalWritten += UInt64(written)
                }

                var offset = try file.seek(offset: 0, from: .current)
                if offset > totalWritten {
                    offset = Int64(totalWritten)
                }
                if let shouldContinue = progress?(Int64(totalWritten)), !shouldContinue {
                    break
                }
            }
        }

        try file.fsync()
    }
}


/// Tracks whether the consumer of `contents(atPath:range:)`'s stream is
/// still interested, so the producing loop can stop once it is terminated.
final class StreamConsumerGone: @unchecked Sendable {
    private let lock = NSLock()
    private var gone = false

    func set() {
        lock.lock()
        gone = true
        lock.unlock()
    }

    var isGone: Bool {
        lock.lock()
        defer { lock.unlock() }
        return gone
    }
}
