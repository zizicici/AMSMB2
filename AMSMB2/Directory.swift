//
//  Directory.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

/// A directory entry copied out of libsmb2's directory cache.
struct SMB2DirectoryEntry {
    let name: String
    let st: smb2_stat_64
}

/// A directory snapshot. Entries are copied out under a single context
/// lock, so a disconnect while enumerating fails the listing instead of
/// silently truncating it, and iterating reads Swift values only.
final class SMB2Directory: Collection {
    private let entries: [SMB2DirectoryEntry]

    init(_ path: String, on client: SMB2Client) throws {
        let (_, handle) = try client.async_await(dataHandler: OpaquePointer.init) { context, cbPtr -> Int32 in
            smb2_opendir_async(context, path, SMB2Client.generic_handler, cbPtr)
        }
        let dir = UnsafeMutablePointer<smb2dir>(handle)

        // Drain under one lock hold: releasing the context lock between
        // reads would let a concurrent failure destroy the context, and a
        // destroyed context must surface as an error rather than look
        // like the end of the directory.
        self.entries = try client.withThreadSafeContext { context -> [SMB2DirectoryEntry] in
            // Entry names point into the directory handle, so they are
            // copied into Swift strings before it is closed.
            defer { smb2_closedir(context, dir) }
            smb2_rewinddir(context, dir)
            var entries = [SMB2DirectoryEntry]()
            while let entry = smb2_readdir(context, dir)?.pointee {
                guard let name = entry.name else { continue }
                entries.append(.init(name: String(cString: name), st: entry.st))
            }
            return entries
        }
    }

    func makeIterator() -> IndexingIterator<[SMB2DirectoryEntry]> {
        entries.makeIterator()
    }

    var startIndex: Int {
        entries.startIndex
    }

    var endIndex: Int {
        entries.endIndex
    }

    var count: Int {
        entries.count
    }

    subscript(index: Int) -> SMB2DirectoryEntry {
        entries[index]
    }

    func index(after index: Int) -> Int {
        entries.index(after: index)
    }
}
