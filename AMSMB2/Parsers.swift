//
//  Parsers.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/29/19.
//  Copyright © 2019 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

struct EmptyReply: DecodableResponse {
    init(data _: Data) throws {}
    init(_: SMB2Client, _: UnsafeMutableRawPointer?) throws {}
}

extension String {
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try String(cString: dataPtr.unwrap().assumingMemoryBound(to: Int8.self))
    }
}

extension Array where Element == SMB2Share {
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        defer { try? client.withThreadSafeContext { smb2_free_data($0, dataPtr) } }
        let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_share_enum_reply.self).pointee
        // The wrapper only requests level-1 enumeration.
        guard reply.level == SMB2_SHARE_INFO_1.rawValue, let info = reply.share_info.info_1 else {
            self = []
            return
        }
        self = (0..<Int(clamping: reply.entries_read)).map { index in
            SMB2Share(
                // NDR unique pointers are legally NULL for empty name/remark.
                name: info[index].netname.map { String(cString: $0) } ?? "",
                props: .init(rawValue: info[index].type),
                comment: info[index].remark.map { String(cString: $0) } ?? ""
            )
        }
    }
}

extension Array where Element == SMB2FileChangeInfo {
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        var result = [SMB2FileChangeInfo]()
        guard let dataPtr else {
            self = result
            return
        }
        // The notify chain is allocated by libsmb2 for the callback and is
        // owned by the callback receiver (its own sync wrapper frees it);
        // release it once the entries are copied into Swift values.
        defer {
            try? client.withThreadSafeContext {
                free_smb2_file_notify_change_information(
                    $0, dataPtr.assumingMemoryBound(to: smb2_file_notify_change_information.self)
                )
            }
        }
        dataPtr.withMemoryRebound(to: smb2_file_notify_change_information.self, capacity: 1) { head in
            // Walk node by node: appending the current node and then
            // advancing (appending the head before the loop and the node
            // before its successor inside it duplicated the first entry and
            // dropped the last).
            var current: UnsafeMutablePointer<smb2_file_notify_change_information>? = head
            while let node = current {
                if node.pointee.name != nil {
                    result.append(.init(node.pointee))
                }
                current = node.pointee.next
            }
        }
        self = result
    }
}

extension OpaquePointer {
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try OpaquePointer(dataPtr.unwrap())
    }
}

struct SMB2FileID: RawRepresentable {
    let rawValue: smb2_file_id
    
    init?(rawValue: smb2_file_id) {
        self.rawValue = rawValue
    }
    
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self.rawValue = try dataPtr.unwrap().assumingMemoryBound(to: smb2_create_reply.self).pointee
            .file_id
    }
}

extension DecodableResponse {
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_ioctl_reply.self).pointee
        guard reply.output_count > 0, let output = reply.output else {
            self = try Self(data: .init())
            return
        }
        // The copychunk family decodes into fixed-size structs; output_count still
        // carries the raw wire length and would overrun the allocation when copied.
        let decodedLength: Int
        switch reply.ctl_code {
        case UInt32(SMB2_FSCTL_SRV_REQUEST_RESUME_KEY):
            decodedLength = Int(SMB2_SRV_COPYCHUNK_RESUME_KEY_SIZE)
        case UInt32(SMB2_FSCTL_SRV_COPYCHUNK), UInt32(SMB2_FSCTL_SRV_COPYCHUNK_WRITE):
            decodedLength = MemoryLayout<smb2_srv_copychunk_reply>.stride
        case UInt32(SMB2_FSCTL_GET_REPARSE_POINT):
            // The C side decodes this into a fixed-size struct regardless of
            // the server's declared output_count.
            decodedLength = MemoryLayout<smb2_reparse_data_buffer>.stride
        default:
            decodedLength = Int(clamping: reply.output_count)
        }
        let length = min(decodedLength, Int(clamping: reply.output_count))
// Check memory validity in order to prevent crash on invalid pointers.
// Best-effort only: msync() can also fail with ENOMEM for a buffer that ends
// on the final page of a mapping, in which case a legitimate (but truncated)
// response is silently replaced by empty data. That is the safe direction:
// a bogus pointer never gets decoded.
#if canImport(Darwin)
        let pageSize = sysconf(_SC_PAGESIZE)
        let base = UnsafeMutableRawPointer(bitPattern: (size_t(bitPattern: output) / pageSize) * pageSize)
        // Cover the whole decoded range, not just the first page: a mapping
        // can end between base+pageSize and base+length.
        if msync(base, length, MS_ASYNC) != 0 {
            self = try Self(data: .init())
            return
        }
#endif
        defer { try? client.withThreadSafeContext { smb2_free_data($0, output) } }
        let data = Data(bytes: output, count: length)
        self = try Self(data: data)
    }
}
