//
//  SMB2ManagerTests.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import XCTest

import Atomics
#if canImport(Darwin)
@preconcurrency import Darwin
#else
import FoundationNetworking
#endif
@testable import AMSMB2

private func folderName(postfix: String = "", name: String = #function) -> String {
    "\(name.trimmingCharacters(in: .init(charactersIn: "()")))\(postfix)"
}

private func fileName(postfix: String = "", name: String = #function) -> String {
    "\(name.trimmingCharacters(in: .init(charactersIn: "()")))\(postfix).dat"
}

class SMB2ManagerTests: XCTestCase, @unchecked Sendable {
    /// These tests need a live SMB server. Skip them when the environment is
    /// not configured instead of trapping on `ProcessInfo...["SMB_SERVER"]!`,
    /// which would abort the whole test run.
    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["SMB_SERVER"] != nil
                && ProcessInfo.processInfo.environment["SMB_SHARE"] != nil,
            "Set SMB_SERVER and SMB_SHARE (plus SMB_USER/SMB_PASSWORD as needed) to run these tests."
        )
    }

    override func setUp() {
        super.setUp()
        // Put setup code here. This method will be called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    // Change server address and testing share
    lazy var server: URL = .init(string: ProcessInfo.processInfo.environment["SMB_SERVER"]!)!

    lazy var share: String = ProcessInfo.processInfo.environment["SMB_SHARE"]!

    lazy var credential: URLCredential? = {
        if let user = ProcessInfo.processInfo.environment["SMB_USER"],
           let pass = ProcessInfo.processInfo.environment["SMB_PASSWORD"]
        {
            return URLCredential(user: user, password: pass, persistence: .forSession)
        } else {
            return nil
        }
    }()

    lazy var encrypted: Bool = ProcessInfo.processInfo.environment["SMB_ENCRYPTED"] == "1"

    func testConnectDisconnect() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.disconnectShare(gracefully: false)
        try await smb.connectShare(name: share, encrypted: encrypted)
    }

    func testAutomaticEncryptionWhenRequired() async throws {
        guard let requiredShare = ProcessInfo.processInfo.environment["SMB_ENCRYPTION_REQUIRED_SHARE"] else {
            throw XCTSkip("Set SMB_ENCRYPTION_REQUIRED_SHARE to a share that requires encryption.")
        }
        let smb = SMB2Manager(url: server, credential: credential)!
        let path = fileName()
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try? await smb.disconnectShare(gracefully: true)
        }

        // The default must allow the server to require encryption.
        try await smb.connectShare(name: requiredShare)
        let data = Data("automatic encryption".utf8)
        try await smb.write(data: data, toPath: path, progress: nil)
        let contents = try await smb.contents(atPath: path)
        XCTAssertEqual(contents, data)
        try await smb.echo()
    }

    func testShareEnum() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!

        let shares = try await smb.listShares()
        XCTAssertFalse(shares.isEmpty)
        XCTAssert(shares.contains(where: { $0.name == self.share }))

        let hiddenShares = try await smb.listShares(enumerateHidden: true)
        XCTAssertFalse(hiddenShares.isEmpty)
        XCTAssert(hiddenShares.contains(where: { $0.name == self.share }))
        XCTAssertGreaterThanOrEqual(hiddenShares.count, shares.count)

    }

    func testFileSystemAttributes() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        let fsAttributes = try await smb.attributesOfFileSystem(forPath: "/")
        XCTAssertFalse(fsAttributes.isEmpty)
        XCTAssertGreaterThanOrEqual(fsAttributes[.systemSize] as! Int64, 0)
        XCTAssertGreaterThanOrEqual(fsAttributes[.systemFreeSize] as! Int64, 0)
        XCTAssertGreaterThanOrEqual(
            fsAttributes[.systemSize] as! Int64, fsAttributes[.systemFreeSize] as! Int64
        )
    }
    
    func testFileAttributes() async throws {
        let file = fileName()
        let size: Int = random(max: 0x000800)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        let initialAttribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertNotNil(initialAttribs.name)
        XCTAssertNotNil(initialAttribs.contentModificationDate)
        XCTAssertNotNil(initialAttribs.creationDate)
        XCTAssertGreaterThanOrEqual(initialAttribs.contentModificationDate!, initialAttribs.creationDate!)
        XCTAssertEqual(initialAttribs[.isHiddenKey] as? Bool, nil)
        
        try await smb.setAttributes(attributes: [
            .creationDateKey: Date(timeIntervalSinceReferenceDate: 0),
            .isHiddenKey: true,
        ], ofItemAtPath: file)
        
        let newAttribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertEqual(initialAttribs.contentModificationDate, newAttribs.contentModificationDate)
        XCTAssertEqual(newAttribs.creationDate, Date(timeIntervalSinceReferenceDate: 0))
    }
    
    func testFileRename() async throws {
        let file = fileName()
        let renamedFile = fileName(postfix: "Renamed")
        let size: Int = random(max: 0x000800)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
            try? await smb.removeFile(atPath: renamedFile)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        try await smb.moveItem(atPath: file, toPath: renamedFile)
        let renamedData = try await smb.contents(atPath: renamedFile)
        XCTAssertEqual(data, renamedData)
    }
    
    func testFileTruncate() async throws {
        let file = fileName()
        let size: Int = random(min: 0x000401, max: 0x002000)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        try await smb.truncateFile(atPath: file, atOffset: UInt64(min(0x000200, size / 2)))
        let truncData = try await smb.contents(atPath: file)
        XCTAssertEqual(truncData.count, 0x000200)
        XCTAssertEqual(data.prefix(truncData.count), truncData)
    }
    
    func testListing() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        // The assertions below need at least one entry; a fresh share can be
        // empty, so create one (this test used to pass only when earlier
        // runs or other agents had left files behind).
        let seed = fileName()
        addTeardownBlock {
            try? await smb.removeFile(atPath: seed)
        }
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: Data([0x01]), toPath: seed, progress: nil)
        let contents = try await smb.contentsOfDirectory(atPath: "/")
        XCTAssertFalse(contents.isEmpty)
        XCTAssertNotNil(contents.first)
        guard let file = contents.first else { return }
        XCTAssertNotNil(file.name)
        XCTAssertNotNil(file.contentModificationDate)
        XCTAssertNotNil(file.creationDate)
        XCTAssertGreaterThanOrEqual(file.contentModificationDate!, file.creationDate!)
    }

    func testSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        let contents = try await smb.contentsOfDirectory(atPath: "/")
        if let symlink = contents.first(where: { $0.isSymbolicLink }) {
            let destination = try await smb.destinationOfSymbolicLink(atPath: symlink.path!)
            XCTAssert(
                !destination.trimmingCharacters(
                    in: CharacterSet.alphanumerics.inverted
                ).isEmpty
            )
        }
    }
    
    func testCreateSymlinkFailureLeavesNoFile() async throws {
        // createSymbolicLink creates the file first and then sets the
        // reparse data. On a server without reparse-point support the
        // second step fails, and the library used to leave the empty
        // placeholder behind. No teardown removal here on purpose: the
        // library itself must have cleaned up.
        let smb = SMB2Manager(url: server, credential: credential)!
        let link = fileName(postfix: "Residue")
        try await smb.connectShare(name: share, encrypted: encrypted)
        do {
            try await smb.createSymbolicLink(atPath: link, withDestinationPath: "nowhere")
        } catch {
            do {
                _ = try await smb.attributesOfItem(atPath: link)
                try? await smb.removeFile(atPath: link)
                XCTFail("a failed createSymbolicLink left a file behind")
            } catch {
                // Expected: nothing exists at the path.
            }
            return
        }
        try? await smb.removeFile(atPath: link)
        throw XCTSkip("This server supports reparse points; the failure path is not reachable here.")
    }

    func testCreateSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let target = fileName(postfix: "Target")
        let link = fileName()
        let data = randomData(size: 0x000800)
        
        addTeardownBlock {
            try? await smb.removeFile(atPath: target)
            try? await smb.removeFile(atPath: link)
        }
        
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: target, progress: nil)
        try await smb.createSymbolicLink(atPath: link, withDestinationPath: target)
        
        let attribs = try await smb.attributesOfItem(atPath: link)
        XCTAssertNotNil(attribs.contentModificationDate)
        XCTAssertNotNil(attribs.creationDate)
        XCTAssert(attribs.isSymbolicLink)
        XCTAssertEqual(attribs.fileResourceType, URLFileResourceType.symbolicLink)
        
        let destination = try await smb.destinationOfSymbolicLink(atPath: link)
        XCTAssertEqual(destination, target)
    }
    
    func testRemoveSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let target = fileName(postfix: "Target")
        let link = fileName()
        let data = randomData(size: 0x000800)
        
        addTeardownBlock {
            try? await smb.removeFile(atPath: target)
            try? await smb.removeFile(atPath: link)
        }
        
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: target, progress: nil)
        try await smb.createSymbolicLink(atPath: link, withDestinationPath: target)
        try await smb.removeFile(atPath: link)
        
        do {
            _ = try await smb.destinationOfSymbolicLink(atPath: link)
            XCTAssert(false, "Destination should not exist")
        } catch {}
    }

    func testDirectoryOperation() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "testEmpty")
        try await smb.removeDirectory(atPath: "testEmpty", recursive: false)

        try await smb.createDirectory(atPath: "testFull")
        try await smb.createDirectory(atPath: "testFull/test")
        try await smb.removeDirectory(atPath: "testFull", recursive: true)
    }

    func testZeroWriteRead() async throws {
        let size = 0
        try await readWrite(size: size, function: #function)
    }

    func testSmallWriteRead() async throws {
        let size: Int = random(max: 14)
        try await readWrite(size: size, function: #function)
    }

    private var optimizedSize = 1024 * 1024 // 1MB
    private var maxSize = 4 * 1024 * 1024 // 4MB

    func testMediumWriteRead() async throws {
        let size = 15 + random(max: optimizedSize - 15)
        try await readWrite(size: size, function: #function)
    }

    func testLargeWriteRead() async throws {
        let size: Int = maxSize * 3 + random(max: optimizedSize)
        try await readWrite(size: size, checkLeak: false, function: #function)
    }

    private func readWrite(size: Int, checkLeak: Bool = false, function: String) async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)
        let baseMemUsage = report_memory()

        addTeardownBlock {
            try? await smb.removeFile(atPath: fileName(name: function))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(
            data: data, toPath: fileName(name: function),
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(function, "uploaded:", progress, "of", size)
                return true
            }
        )
        if checkLeak {
            XCTAssertLessThan(report_memory() - baseMemUsage, 2 * size)
        }

        let rdata = try await smb.contents(
            atPath: fileName(name: function),
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertEqual(total, Int64(data.count))
                print(function, "downloaded:", progress, "of", total)
                return true
            }
        )
        if checkLeak {
            XCTAssertLessThan(report_memory() - baseMemUsage, 3 * size)
        }
        XCTAssertEqual(data, rdata)

        let trdata = try await smb.contents(
            atPath: fileName(name: function), range: ..<UInt64(10), progress: nil
        )
        XCTAssertEqual(data.prefix(10), trdata)

        if checkLeak {
            print("\(function) after free memory usage:", report_memory() - baseMemUsage)
            XCTAssertLessThan(report_memory() - baseMemUsage, 3 * size)
        }
    }

    func testChunkedLoad() async throws {
        let file = fileName()
        let size: Int = random(max: 0xf00000)
        let smb = SMB2Manager(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)

        return try await withCheckedThrowingContinuation { continuation in
            let cachedOffset: ManagedAtomic<Int64> = .init(0)
            smb.contents(atPath: file) { offset, _, chunk in
                XCTAssertEqual(offset, cachedOffset.load(ordering: .relaxed))
                _ = cachedOffset.loadThenWrappingIncrement(by: Int64(chunk.count), ordering: .relaxed)
                XCTAssertEqual(data[Int(offset)..<Int(cachedOffset.load(ordering: .relaxed))], chunk)
                return true
            } completionHandler: { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    func testUploadDownload() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = max(random(max: 0xf00000), 4096)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let replacementURL = dummyFile(size: 1, name: "testUploadDownloadReplacement")
        let dlURL = url.appendingPathExtension("downloaded")

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: replacementURL)
            try? FileManager.default.removeItem(at: dlURL)
            try? await smb.removeFile(atPath: fileName())
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.uploadItem(
            at: url, toPath: fileName(),
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }
        )
        do {
            try await smb.uploadItem(at: url, toPath: fileName(), progress: nil)
            XCTAssert(false, "Upload must fail.")
        } catch {
            let error = error as? POSIXError
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.code, POSIXErrorCode.EEXIST)
        }
        try await smb.uploadItem(at: replacementURL, toPath: fileName(), overwrite: true, progress: nil)
        let attributes = try await smb.attributesOfItem(atPath: fileName())
        XCTAssertEqual((attributes[.fileSizeKey] as? NSNumber)?.intValue, 1)

        try await smb.downloadItem(
            atPath: fileName(), to: dlURL,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertGreaterThan(total, 0)
                print(#function, "downloaded:", progress, "of", total)
                return true
            }
        )
        XCTAssert(FileManager.default.contentsEqual(atPath: replacementURL.path, andPath: dlURL.path))

        try await smb.echo()
    }

    func testStreamUploadDownload() async throws {
        let file = fileName()
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0xf00000)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")
        let inputStream = AsyncThrowingStream(url: url)

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(
            stream: inputStream, toPath: file,
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }
        )
        
        try await smb.downloadItem(
            atPath: file, to: dlURL,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertGreaterThan(total, 0)
                print(#function, "downloaded:", progress, "of", total)
                return true
            }
        )
        XCTAssert(FileManager.default.contentsEqual(atPath: url.path, andPath: dlURL.path))
    }
    
    func testSimultaneousUpload() async throws {
        let redownload = false
        let fileNums = 5
        let files = (1...fileNums).map { fileName(postfix: "\($0)") }
        let urls = (1...fileNums).map {
            let size: Int = random(max: 0xf00000)
            print(#function, "test size \($0):", size)
            return self.dummyFile(size: size)
        }
        
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        
        addTeardownBlock {
            try? urls.forEach(FileManager.default.removeItem(at:))
            try? urls
                .map { $0.appendingPathExtension("download") }
                .forEach(FileManager.default.removeItem(at:))
            await withTaskGroup(of: Void.self) { group in
                for file in files {
                    group.addTask {
                        try? await smb.removeFile(atPath: file)
                    }
                }
                await group.waitForAll()
            }
            for file in files {
                try? await smb.removeFile(atPath: file)
            }
        }
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (file, url) in zip(files, urls) {
                group.addTask {
                    try await smb.uploadItem(at: url, toPath: file, progress: nil)
                }
            }
            
            try await group.waitForAll()
        }
        
        guard redownload else { return }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (file, url) in zip(files, urls) {
                group.addTask {
                    try await smb.downloadItem(atPath: file, to: url.appendingPathExtension("download"), progress: nil)
                }
            }
            
            try await group.waitForAll()
        }
    }

    func testTruncate() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0xf00000)
        let url = dummyFile(size: size)
        let file = fileName()

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? await smb.removeFile(atPath: file)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.uploadItem(at: url, toPath: file, progress: nil)
        try await smb.truncateFile(atPath: file, atOffset: 0x10000)
        let attribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertEqual(attribs.fileSize, 0x10000)

        try await smb.echo()
    }

    func testCopy() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0x400000)
        print(#function, "test size:", size)
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: fileName())
            try? await smb.removeFile(atPath: fileName(postfix: "Dest"))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: fileName(), progress: nil)
        try await smb.copyItem(
            atPath: fileName(), toPath: fileName(postfix: "Dest"), recursive: false,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertEqual(total, Int64(data.count))
                print(#function, "copied:", progress, "of", total)
                return true
            }
        )
        let attribs = try await smb.attributesOfItem(atPath: fileName(postfix: "Dest"))
        XCTAssertEqual(attribs.fileSize, Int64(data.count))
    }

    func testMove() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        addTeardownBlock {
            try? await smb.removeFile(atPath: folderName())
            try? await smb.removeFile(atPath: folderName(postfix: "Dest"))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: folderName())
        try await smb.moveItem(atPath: folderName(), toPath: folderName(postfix: "Dest"))
    }

    func testRecursiveCopyRemove() async throws {
        let root = folderName()
        let rootCopy = folderName(postfix: " Copy")
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: root, recursive: true)
            try? await smb.removeDirectory(atPath: rootCopy, recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: root)
        try await smb.createDirectory(atPath: "\(root)/subdir")
        try await smb.write(data: [0x01, 0x02, 0x03], toPath: "\(root)/file", progress: nil)
        try await smb.write(data: [0x04], toPath: "\(root)/subdir/nested", progress: nil)
        try await smb.write(data: [0x05], toPath: "\(root)/second", progress: nil)
        try await smb.copyItem(atPath: root, toPath: rootCopy, recursive: true, progress: nil)
        // Assert every file, not just the first: a copy that silently stops
        // after the first entry used to pass this test.
        let attribs = try await smb.attributesOfItem(atPath: "\(rootCopy)/file")
        XCTAssertEqual(attribs.fileSize, 3)
        let nested = try await smb.contents(atPath: "\(rootCopy)/subdir/nested")
        let second = try await smb.contents(atPath: "\(rootCopy)/second")
        XCTAssertEqual(nested, Data([0x04]))
        XCTAssertEqual(second, Data([0x05]))
    }

    func testCopyItemTrailingSlashLandsChildrenInsideDestination() async throws {
        // A trailing slash on the source directory used to concatenate the
        // destination with each child name ("dest" + "file") and scatter the
        // children across the share root instead of inside the destination.
        let root = folderName()
        let rootCopy = folderName(postfix: "SlashDest")
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: root, recursive: true)
            try? await smb.removeDirectory(atPath: rootCopy, recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: root)
        try await smb.write(data: Data([0x01]), toPath: "\(root)/a", progress: nil)
        try await smb.write(data: Data([0x02, 0x03]), toPath: "\(root)/b", progress: nil)
        try await smb.copyItem(atPath: "\(root)/", toPath: rootCopy, recursive: true, progress: nil)
        let copiedA = try await smb.contents(atPath: "\(rootCopy)/a")
        let copiedB = try await smb.contents(atPath: "\(rootCopy)/b")
        XCTAssertEqual(copiedA, Data([0x01]))
        XCTAssertEqual(copiedB, Data([0x02, 0x03]))
    }

    func testDeprecatedCopyContentsOfItemCopiesEveryFile() async throws {
        // The deprecated read/write copy path used to stop silently after
        // the first file of a recursive copy: EOF of one file was reported
        // through the cancellation path and read as "user aborted".
        let root = folderName(postfix: "RW")
        let rootCopy = folderName(postfix: "RWCopy")
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: root, recursive: true)
            try? await smb.removeDirectory(atPath: rootCopy, recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: root)
        let payloads = ["a": Data([0x0A]), "b": Data([0x0B, 0x0C]), "c": Data([0x0D])]
        for (name, data) in payloads {
            try await smb.write(data: data, toPath: "\(root)/\(name)", progress: nil)
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            smb.copyContentsOfItem(
                atPath: root, toPath: rootCopy, recursive: true, progress: { _, _ in true }
            ) { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            }
        }
        for (name, data) in payloads {
            let copied = try await smb.contents(atPath: "\(rootCopy)/\(name)")
            XCTAssertEqual(copied, data, "every file must be copied, not just the first")
        }
    }

    func testConnectIgnoresNTLMUserFileEnv() async throws {
        // Credentials come from the manager, never from NTLM_USER_FILE:
        // connect passes a NULL user to libsmb2, so the env var is never
        // consulted at connect time. Passing any non-NULL user (including
        // "") makes libsmb2 re-read the file and clear the configured
        // password, failing this test.
        guard credential != nil else {
            throw XCTSkip("Set SMB_USER and SMB_PASSWORD to verify credential authentication.")
        }
        // setenv is process-global: preserve and restore any pre-existing
        // value instead of unconditionally unsetting it.
        let previous = ProcessInfo.processInfo.environment["NTLM_USER_FILE"]
        setenv("NTLM_USER_FILE", "/dev/null", 1)
        defer {
            if let previous {
                setenv("NTLM_USER_FILE", previous, 1)
            } else {
                unsetenv("NTLM_USER_FILE")
            }
        }
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.echo()
        try await smb.disconnectShare(gracefully: true)
    }

    func testDeepRecursiveListingAndRemoval() async throws {
        // listDirectory used to recurse per subdirectory on 512 KiB GCD
        // worker stacks and crashed around 340 levels deep in debug builds
        // (~1500 in release) — with the depth driven entirely by the
        // server's replies. 600 levels is comfortably past the debug
        // boundary while staying under the server's PATH_MAX.
        let root = folderName(postfix: "Deep")
        let smb = SMB2Manager(url: server, credential: credential)!
        addTeardownBlock {
            try? await smb.removeDirectory(atPath: root, recursive: true)
            try? await smb.disconnectShare(gracefully: true)
        }
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: root)
        var current = root
        for level in 0..<600 {
            current += "/d"
            try await smb.createDirectory(atPath: current)
            if level % 100 == 0 {
                try await smb.write(data: Data([UInt8(level % 251)]), toPath: current + "/f", progress: nil)
            }
        }
        let entries = try await smb.contentsOfDirectory(atPath: root, recursive: true)
        XCTAssertEqual(entries.count, 600 + 6, "600 directories and 6 marker files")
        try await smb.removeDirectory(atPath: root, recursive: true)
    }

    func testRecursiveListingOrderMatchesReferencePreOrder() async throws {
        // Locks the "iterative DFS preserves the recursive pre-order exactly"
        // promise: a directory's entries, then each subtree fully before the
        // next sibling. Reference implemented with the old shape (per-level
        // non-recursive enumeration + recursion in listing order).
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        defer { addTeardownBlock { try? await smb.removeDirectory(atPath: "ord-lock", recursive: true) } }

        try? await smb.removeDirectory(atPath: "ord-lock", recursive: true)
        try await smb.createDirectory(atPath: "ord-lock")

        // Mirrors the old recursive shape: list one level (pathKey carries
        // the library's own formatting — trailing slash on directories),
        // then recurse into each subdirectory in listing order.
        func referenceList(_ path: String) async throws -> [String] {
            let entries = try await smb.contentsOfDirectory(atPath: path, recursive: false)
            var out = entries.compactMap { $0[.pathKey] as? String }
            for entry in entries where (entry[.isDirectoryKey] as? Bool) == true {
                if let subPath = entry[.pathKey] as? String {
                    out.append(contentsOf: try await referenceList(subPath))
                }
            }
            return out
        }

        for tree in 0..<6 {
            let root = tree == 0 ? "ord-lock/chain" : "ord-lock/t\(tree)"
            try await smb.createDirectory(atPath: root)
            // chain of 8
            var current = root
            for _ in 0..<8 { current += "/d"; try await smb.createDirectory(atPath: current) }
            // wide fan of 5 under root with one file each
            for i in 0..<5 {
                try await smb.write(data: Data([UInt8(i)]), toPath: "\(root)/f\(i)", progress: nil)
            }
            // one nested wide level under the first dir
            try await smb.createDirectory(atPath: "\(root)/d/sub")
            for i in 0..<3 { try await smb.write(data: Data([UInt8(i)]), toPath: "\(root)/d/sub/g\(i)", progress: nil) }

            let produced = try await smb.contentsOfDirectory(atPath: root, recursive: true)
                .compactMap { $0[.pathKey] as? String }
            let reference = try await referenceList(root)
            XCTAssertEqual(produced, reference, "tree \(root): iterative DFS must equal the recursive pre-order")
        }
    }

    func testCreateSymlinkAbsolutePathReachesReparseStage() async throws {
        // The full-parameter open used to skip trimming, so an absolute path
        // went on the wire as "\dir\link" and Samba's CREATE rejected it
        // with STATUS_INVALID_PARAMETER before the reparse step was ever
        // reached. After the fix the failure (on servers without reparse
        // support) must be the FSCTL one, not the CREATE one.
        let smb = SMB2Manager(url: server, credential: credential)!
        let link = "/\(fileName(postfix: "Abs"))"
        try await smb.connectShare(name: share, encrypted: encrypted)
        do {
            try await smb.createSymbolicLink(atPath: link, withDestinationPath: "target")
            try? await smb.removeFile(atPath: link)
            throw XCTSkip("Server supports reparse points; the CREATE-stage failure path is not reachable here.")
        } catch let skip as XCTSkip { throw skip }
        catch {
            let description = (error as? LocalizedError)?.errorDescription ?? ""
            XCTAssertFalse(
                description.contains("0xC000000D"),
                "absolute path must not fail CREATE with STATUS_INVALID_PARAMETER; got: \(description)"
            )
        }
    }

    func testRemove() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: folderName(), recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "\(folderName())")
        try await smb.createDirectory(atPath: "\(folderName())/subdir")
        try await smb.write(data: Data(), toPath: "\(folderName())/file", progress: nil)
        try await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
    }
    
    func testMonitor() async throws {
        try XCTSkipIf(true)
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "\(folderName())")
        try await smb.createDirectory(atPath: "\(folderName())/subdir")
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    let changes = try await smb.monitorItem(atPath: "\(folderName())", for: [.fileName, .recursive])
                    XCTAssert(!changes.isEmpty)
                    print(changes)
                } catch {
                    print(error)
                    throw error
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                try await smb.write(data: Data(), toPath: "\(folderName())/file", progress: nil)
            }
            try await group.waitForAll()
        }
        try await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
    }
}

extension SMB2ManagerTests {
    private func random<T: FixedWidthInteger>(min: T = 0, max: T) -> T {
        T.random(in: min...max)
    }

    private func randomData(size: Int = 262_144) -> Data {
        Data((0..<size).map { _ in UInt8.random(in: 0...UInt8.max) })
    }
    
    private func dummyFile(size: Int = 262_144, name: String = #function) -> URL {
        let name = fileName(name: name)
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)

        if FileManager.default.fileExists(atPath: url.path) {
            try! FileManager.default.removeItem(at: url)
        }

        let data = randomData(size: size)
        try! data.write(to: url)
        return url
    }
    
    private func report_memory() -> Int {
#if canImport(Darwin)
        var taskInfo = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &taskInfo) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }

        if kerr == KERN_SUCCESS {
            return Int(taskInfo.resident_size)
        } else {
            return -1
        }
#else
        return 0
#endif
    }
}

/// NSCoding / Codable / NSCopy coverage that does not need a live SMB server,
/// kept out of SMB2ManagerTests so its server-skip guard does not hide it.
final class SMB2ManagerCodingTests: XCTestCase {
    @available(iOS 11.0, macOS 10.13, tvOS 11.0, *)
    func testNSCodable() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, credential: credential)
        XCTAssertNotNil(smb)
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.encode(smb, forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        let data = archiver.encodedData
        XCTAssertNil(archiver.error)
        XCTAssertFalse(data.isEmpty)
        let unarchiver = try! NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver.decodingFailurePolicy = .setErrorAndReturn
        unarchiver.requiresSecureCoding = true
        let decodedSMB = unarchiver.decodeObject(
            of: SMB2Manager.self, forKey: NSKeyedArchiveRootObjectKey
        )
        XCTAssertNotNil(decodedSMB)
        XCTAssertEqual(smb?.url, decodedSMB?.url)
        XCTAssertEqual(smb?.timeout, decodedSMB?.timeout)
        XCTAssertNil(unarchiver.error)
    }

    func testCoding() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, domain: "", credential: credential)
        XCTAssertNotNil(smb)
        do {
            let encoder = JSONEncoder()
            let json = try encoder.encode(smb!)
            XCTAssertFalse(json.isEmpty)
            let decoder = JSONDecoder()
            let decodedSMB = try decoder.decode(SMB2Manager.self, from: json)
            XCTAssertEqual(smb!.url, decodedSMB.url)
            XCTAssertEqual(smb!.timeout, decodedSMB.timeout)

            let errorJson = String(data: json, encoding: .utf8)!.replacingOccurrences(
                of: "smb:", with: "smb2:"
            ).data(using: .utf8)!
            XCTAssertThrowsError(try decoder.decode(SMB2Manager.self, from: errorJson))
        } catch {
            XCTAssert(false, error.localizedDescription)
        }
    }

    func testNSCopy() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, domain: "", credential: credential)!
        let smbCopy = smb.copy() as! SMB2Manager
        XCTAssertEqual(smb.url, smbCopy.url)
    }

    /// Codable/NSCoding/copy must preserve every credential field and a
    /// non-default timeout — historically these were only checked for url.
    private func fidelityRoundTrip(_ make: () -> SMB2Manager?) throws {
        let original = try XCTUnwrap(make())
        original.timeout = 77

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys] // key order is otherwise nondeterministic
        let json = try encoder.encode(original)
        let decoded = try JSONDecoder().decode(SMB2Manager.self, from: json)
        XCTAssertEqual(try encoder.encode(decoded), json, "Codable round-trip lost a field")

        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.encode(original, forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        let unarchived = try XCTUnwrap(
            try NSKeyedUnarchiver(forReadingFrom: archiver.encodedData)
                .decodeObject(of: SMB2Manager.self, forKey: NSKeyedArchiveRootObjectKey)
        )
        XCTAssertEqual(try encoder.encode(unarchived), json, "NSCoding round-trip lost a field")

        let copied = original.copy() as! SMB2Manager
        XCTAssertEqual(try encoder.encode(copied), json, "copy() lost a field")
        XCTAssertEqual(original.timeout, 77)
    }

    /// The round-trip comparison above is self-referential on the encoder:
    /// an encode-side field drop is invisible. Assert decoded fields
    /// directly against known values.
    func testCodingFidelityDirectFieldAssertions() throws {
        let original = SMB2Manager(
            url: URL(string: "smb://192.168.1.1/share")!,
            credential: URLCredential(user: "DOM;WS\\secret", password: "p@ss", persistence: .forSession)
        )!
        original.timeout = 42

        let json = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SMB2Manager.self, from: json)
        XCTAssertEqual(decoded.timeout, 42)
        // domain/workstation/user/password round-trip through JSON
        let dict = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: json) as? [String: Any]
        )
        XCTAssertEqual(dict["domain"] as? String, "DOM")
        XCTAssertEqual(dict["workstation"] as? String, "WS")
        XCTAssertEqual(dict["user"] as? String, "secret")
        XCTAssertEqual(dict["password"] as? String, "p@ss")
    }

    func testCodingFidelityPlainUser() throws {
        try fidelityRoundTrip {
            SMB2Manager(
                url: URL(string: "smb://192.168.1.1/share")!,
                credential: URLCredential(user: "user", password: "password", persistence: .forSession)
            )
        }
    }

    func testCodingFidelityDomainAndWorkstation() throws {
        try fidelityRoundTrip {
            SMB2Manager(
                url: URL(string: "smb://192.168.1.1/share")!,
                credential: URLCredential(user: "DOM;WS\\alice", password: "secret", persistence: .forSession)
            )
        }
    }

    func testNSCodingMissingTimeoutDefaultsTo60() throws {
        // An archive stripped of the timeout key used to decode as 0 —
        // "timeouts disabled" — hanging every subsequent operation.
        let original = SMB2Manager(url: URL(string: "smb://192.168.1.1/share")!, credential: nil)!
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.encode(original, forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        var plist = try PropertyListSerialization.propertyList(
            from: archiver.encodedData, options: [], format: nil
        ) as! [String: Any]
        let objects = plist["$objects"] as! [Any]
        var root = objects[1] as! [String: Any]
        root.removeValue(forKey: "timeout")
        plist["$objects"] = [objects[0], root] + objects[2...]
        let stripped = try PropertyListSerialization.data(
            fromPropertyList: plist, format: .binary, options: 0
        )
        let decoded = try XCTUnwrap(
            try NSKeyedUnarchiver(forReadingFrom: stripped)
                .decodeObject(of: SMB2Manager.self, forKey: NSKeyedArchiveRootObjectKey)
        )
        XCTAssertEqual(decoded.timeout, 60)
    }

    func testTimeoutNegativeNormalizesToDisabled() {
        let manager = SMB2Manager(url: URL(string: "smb://127.0.0.1")!, credential: nil)!
        manager.timeout = -5
        XCTAssertEqual(manager.timeout, 0, "negative timeout means 'disabled', not 'immediate timeout'")
    }
}
