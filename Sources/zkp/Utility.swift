//
//  Utility.swift
//  GigaBitcoin/secp256k1.swift
//
//  Copyright (c) 2022 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation

/// An extension for ContiguousBytes providing a convenience property.
extension ContiguousBytes {
    /// A property that returns an array of UInt8 bytes.
    @inlinable
    public var bytes: [UInt8] {
        withUnsafeBytes { bytesPtr in Array(bytesPtr) }
    }
}

/// An extension for Data providing convenience properties and functions.
extension Data {
    /// A property that returns an array of UInt8 bytes.
    @inlinable
    public var bytes: [UInt8] {
        withUnsafeBytes { bytesPtr in Array(bytesPtr) }
    }

    /// Copies data to unsafe mutable bytes of a given value.
    /// - Parameter value: The inout value to copy the data to.
    public func copyToUnsafeMutableBytes<T>(of value: inout T) {
        _ = Swift.withUnsafeMutableBytes(of: &value) { ptr in
            ptr.copyBytes(from: self.prefix(ptr.count))
        }
    }

    /// A computed property that returns the data with a compact size prefix.
    public var compactSizePrefix: Data {
        let size = UInt64(count)
        var prefix = Data()

        switch size {
        case 0 ..< 253:
            prefix.append(UInt8(size))

        case 253 ... UInt64(UInt16.max):
            prefix.append(253)
            prefix.append(UInt8(size & 0xFF))
            prefix.append(UInt8(size >> 8))

        case (UInt64(UInt16.max) + 1) ... UInt64(UInt32.max):
            prefix.append(254)
            prefix.append(contentsOf: Swift.withUnsafeBytes(of: UInt32(size)) { Array($0) })

        default:
            prefix.append(255)
            prefix.append(contentsOf: Swift.withUnsafeBytes(of: size) { Array($0) })
        }

        return prefix + self
    }
}

/// An extension for Int32 providing a convenience property.
extension Int32 {
    /// A property that returns a Bool representation of the Int32 value.
    var boolValue: Bool {
        Bool(truncating: NSNumber(value: self))
    }
}

/// An extension for secp256k1_ecdsa_signature providing a convenience property.
extension secp256k1_ecdsa_signature {
    /// A property that returns the Data representation of the `secp256k1_ecdsa_signature` object.
    public var dataValue: Data {
        var mutableSig = self
        return Data(bytes: &mutableSig.data, count: MemoryLayout.size(ofValue: data))
    }
}

/// An extension for secp256k1_ecdsa_recoverable_signature providing a convenience property.
extension secp256k1_ecdsa_recoverable_signature {
    /// A property that returns the Data representation of the `secp256k1_ecdsa_recoverable_signature` object.
    public var dataValue: Data {
        var mutableSig = self
        return Data(bytes: &mutableSig.data, count: MemoryLayout.size(ofValue: data))
    }
}

/// An extension for String providing convenience initializers and properties for working with bytes.
extension String {
    /// Initializes a String from a byte array using the `hexString` property from the `BytesUtil.swift` DataProtocol
    /// extension.
    /// - Parameter bytes: A byte array to initialize the String.
    public init(bytes: some DataProtocol) {
        self.init()
        self = bytes.hexString
    }

    /// A convenience property that returns a byte array from a hexadecimal string.
    /// Backed by the `BytesUtil.swift` Array extension initializer.
    /// - Throws: `ByteHexEncodingErrors` for invalid string or hex value.
    public var bytes: [UInt8] {
        get throws {
            // The `BytesUtil.swift` Array extension expects lowercase strings.
            try Array(hexString: lowercased())
        }
    }
}
