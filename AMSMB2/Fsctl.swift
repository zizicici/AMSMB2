//
//  Fsctl.swift
//  AMSMB2
//
//  Created by Amir Abbas on 7/10/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

protocol EncodableArgument: ContiguousBytes & DataProtocol where Index == Int, Element == UInt8 {}

extension EncodableArgument {
    var startIndex: Int {
        0
    }

    var endIndex: Int {
        regions.map(\.count).reduce(0, +)
    }

    subscript(index: Int) -> UInt8 {
        let data = regions.joined()
        let index = data.index(data.startIndex, offsetBy: index)
        return data[index]
    }

    subscript(bounds: Range<Index>) -> Data {
        let data = regions.joined()
        let start = data.index(data.startIndex, offsetBy: bounds.lowerBound)
        let end = data.index(data.startIndex, offsetBy: bounds.upperBound)
        return Data(data[start..<end])
    }

    func index(after i: Int) -> Int {
        i + 1
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Data(regions.joined()).withUnsafeBytes(body)
    }
}

protocol DecodableResponse {
    init(data: Data) throws
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws
}

struct AnyDecodableResponse: DecodableResponse {
    private let data: Data

    init(data: Data) {
        self.data = data
    }
}

enum IOCtl {
    struct Command: RawRepresentable, Equatable, Hashable {
        var rawValue: UInt32
        
    }
}

// - MARK: Pipe
extension IOCtl.Command {
}

// - MARK: DFS
extension IOCtl.Command {
}

// - MARK: Reparse Point
extension IOCtl.Command {
    static let setReparsePoint = Self(SMB2_FSCTL_SET_REPARSE_POINT)
    static let deleteReparsePoint = Self(0x0009_00ac)
}

extension IOCtl {
    
    struct SymbolicLinkReparse: DecodableResponse, EncodableArgument {
        typealias Element = UInt8

        private static let headerLength = 20
        private let reparseTag: UInt32 = SMB2_REPARSE_TAG_SYMLINK
        let substituteName: String
        let printName: String
        let isRelative: Bool
        
        init(path: String, printName: String? = nil, isRelative: Bool = false) {
            let path = path.replacingOccurrences(of: "/", with: "\\")
            self.substituteName = path
            self.printName = printName ?? path
            self.isRelative = isRelative
        }

        init(data: Data) throws {
            guard data.scanValue(offset: 0, as: UInt32.self) == reparseTag else {
                throw POSIXError(.invalidArgument, description: nil)
            }
            let count = try data.scanInt(offset: 4, as: UInt16.self).unwrap()
            // ReparseDataLength covers the fields from SubstituteNameOffset
            // through the end of PathBuffer ([MS-FSCC] 2.1.2.4: "the size of
            // the PathBuffer field plus 12"); padded buffers are accepted.
            guard count + 8 <= data.count else { throw POSIXError(.invalidArgument, description: nil) }

            let substituteOffset = try data.scanInt(offset: 8, as: UInt16.self).unwrap()
            let substituteLen = try data.scanInt(offset: 10, as: UInt16.self).unwrap()
            let printOffset = try data.scanInt(offset: 12, as: UInt16.self).unwrap()
            let printLen = try data.scanInt(offset: 14, as: UInt16.self).unwrap()
            let flag = try data.scanValue(offset: 16, as: UInt32.self).unwrap()

            // Names live in PathBuffer, which is the declared data minus
            // the 12 bytes of offset/length fields ([MS-FSCC] 2.1.2.4) —
            // not the padding after it.
            guard count >= 12,
                  substituteOffset + substituteLen <= count - 12,
                  printOffset + printLen <= count - 12
            else { throw POSIXError(.invalidArgument, description: nil) }
            let substituteData = data.dropFirst(
                Int(SymbolicLinkReparse.headerLength + substituteOffset)
            ).prefix(substituteLen)
            let printData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + printOffset))
                .prefix(printLen)
            let substituteName = try String(data: substituteData, encoding: .utf16LittleEndian)
                .unwrap()
            let printName = try String(data: printData, encoding: .utf16LittleEndian).unwrap()

            self.substituteName = substituteName
            self.printName = printName
            self.isRelative = flag & 1 == 1
        }

        var regions: [Data] {
            let substituteData = substituteName.data(using: .utf16LittleEndian)!
            let substituteLen = UInt16(substituteData.count)
            let printData = printName.data(using: .utf16LittleEndian)!
            let printLen = UInt16(printData.count)
            return [
                .init(value: reparseTag),
                // ReparseDataLength: everything from SubstituteNameOffset to
                // the end of PathBuffer, i.e. the 12 bytes of offset/length
                // fields plus the buffer itself ([MS-FSCC] 2.1.2.4).
                .init(value: UInt16(substituteData.count + printData.count + 12)),
                .init(value: 0 as UInt16), // reserved
                .init(value: 0 as UInt16), // substitute offset
                .init(value: substituteLen),
                .init(value: UInt16(substituteData.count)), // print offset
                .init(value: printLen),
                .init(value: UInt32(isRelative ? 1 : 0)),
                .init(substituteData),
                .init(printData),
            ]
        }

        private init() {
            self.substituteName = ""
            self.printName = ""
            self.isRelative = false
        }
    }
    
}
