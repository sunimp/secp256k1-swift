//
//  ECDSA.swift
//  GigaBitcoin/secp256k1.swift
//
//  Copyright (c) 2021 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//

import Foundation

typealias NISTECDSASignature = DERSignature & DataSignature

// MARK: - DataSignature

protocol DataSignature {
    init(dataRepresentation: some DataProtocol) throws
    var dataRepresentation: Data { get }
}

// MARK: - DERSignature

protocol DERSignature {
    init(derRepresentation: some DataProtocol) throws
    var derRepresentation: Data { get throws }
}

// MARK: - CompactSignature

protocol CompactSignature {
    init(compactRepresentation: some DataProtocol) throws
    var compactRepresentation: Data { get throws }
}

// MARK: - secp256k1.Signing.ECDSASignature

/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension secp256k1.Signing {
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature, CompactSignature {
        // MARK: Properties

        /// Returns the data signature.
        /// The raw signature format for ECDSA is r || s
        public var dataRepresentation: Data

        // MARK: Computed Properties

        /// Serialize an ECDSA signature in compact (64 byte) format.
        /// - Throws: If there is a failure parsing signature
        /// - Returns: a 64-byte data representation of the compact serialization
        public var compactRepresentation: Data {
            get throws {
                let context = secp256k1.Context.rawRepresentation
                var signature = secp256k1_ecdsa_signature()
                var compactSignature = [UInt8](repeating: 0, count: secp256k1.ByteLength.signature)

                dataRepresentation.copyToUnsafeMutableBytes(of: &signature.data)

                guard
                    secp256k1_ecdsa_signature_serialize_compact(
                        context,
                        &compactSignature,
                        &signature
                    ).boolValue
                else {
                    throw secp256k1Error.underlyingCryptoError
                }

                return Data(bytes: &compactSignature, count: secp256k1.ByteLength.signature)
            }
        }

        /// A DER-encoded representation of the signature
        /// - Throws: If there is a failure parsing signature
        /// - Returns: a DER representation of the signature
        public var derRepresentation: Data {
            get throws {
                let context = secp256k1.Context.rawRepresentation
                var signature = secp256k1_ecdsa_signature()
                var derSignatureLength = 80
                var derSignature = [UInt8](repeating: 0, count: derSignatureLength)

                dataRepresentation.copyToUnsafeMutableBytes(of: &signature.data)

                guard
                    secp256k1_ecdsa_signature_serialize_der(
                        context,
                        &derSignature,
                        &derSignatureLength,
                        &signature
                    ).boolValue
                else {
                    throw secp256k1Error.underlyingCryptoError
                }

                return Data(bytes: &derSignature, count: derSignatureLength)
            }
        }

        // MARK: Lifecycle

        /// Initializes ECDSASignature from the raw representation.
        /// - Parameters:
        ///   - dataRepresentation: A data representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with the dataRepresentation count
        public init(dataRepresentation: some DataProtocol) throws {
            guard dataRepresentation.count == secp256k1.ByteLength.signature else {
                throw secp256k1Error.incorrectParameterSize
            }

            self.dataRepresentation = Data(dataRepresentation)
        }

        /// Initializes ECDSASignature from the DER representation.
        /// - Parameter derRepresentation: A DER representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with parsing the derRepresentation
        public init(derRepresentation: some DataProtocol) throws {
            let context = secp256k1.Context.rawRepresentation
            let derSignatureBytes = Array(derRepresentation)
            var signature = secp256k1_ecdsa_signature()

            guard
                secp256k1_ecdsa_signature_parse_der(
                    context,
                    &signature,
                    derSignatureBytes,
                    derSignatureBytes.count
                ).boolValue
            else {
                throw secp256k1Error.underlyingCryptoError
            }

            dataRepresentation = signature.dataValue
        }

        /// Initializes ECDSASignature from the Compact representation.
        /// - Parameter derRepresentation: A Compact representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with parsing the derRepresentation
        public init(compactRepresentation: some DataProtocol) throws {
            let context = secp256k1.Context.rawRepresentation
            var signature = secp256k1_ecdsa_signature()

            guard
                secp256k1_ecdsa_signature_parse_compact(
                    context,
                    &signature,
                    Array(compactRepresentation)
                ).boolValue
            else {
                throw secp256k1Error.underlyingCryptoError
            }

            dataRepresentation = signature.dataValue
        }

        /// Initializes ECDSASignature from the raw representation.
        /// - Parameters:
        ///   - dataRepresentation: A data representation of the key as a collection of contiguous bytes.
        /// - Throws: If there is a failure with the dataRepresentation count
        init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == secp256k1.ByteLength.signature else {
                throw secp256k1Error.incorrectParameterSize
            }

            self.dataRepresentation = dataRepresentation
        }

        // MARK: Functions

        /// Invokes the given closure with a buffer pointer covering the raw bytes of the digest.
        /// - Parameter body: A closure that takes a raw buffer pointer to the bytes of the digest and returns the
        /// digest.
        /// - Throws: If there is a failure with underlying `withUnsafeBytes`
        /// - Returns: The signature as returned from the body closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try dataRepresentation.withUnsafeBytes(body)
        }
    }
}

// MARK: - secp256k1.Signing.PrivateKey + DigestSigner

extension secp256k1.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the secp256k1 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature(for digest: some Digest) throws -> secp256k1.Signing.ECDSASignature {
        let context = secp256k1.Context.rawRepresentation
        var signature = secp256k1_ecdsa_signature()

        guard
            secp256k1_ecdsa_sign(
                context,
                &signature,
                Array(digest),
                Array(dataRepresentation),
                nil,
                nil
            ).boolValue
        else {
            throw secp256k1Error.underlyingCryptoError
        }

        return try secp256k1.Signing.ECDSASignature(signature.dataValue)
    }
}

// MARK: - secp256k1.Signing.PrivateKey + Signer

extension secp256k1.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the secp256k1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature(for data: some DataProtocol) throws -> secp256k1.Signing.ECDSASignature {
        try signature(for: SHA256.hash(data: data))
    }
}

// MARK: - secp256k1.Signing.PublicKey + DigestValidator

extension secp256k1.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the secp256k1 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature(_ signature: secp256k1.Signing.ECDSASignature, for digest: some Digest) -> Bool {
        let context = secp256k1.Context.rawRepresentation
        var ecdsaSignature = secp256k1_ecdsa_signature()
        var publicKey = rawRepresentation

        signature.dataRepresentation.copyToUnsafeMutableBytes(of: &ecdsaSignature.data)

        return secp256k1_ecdsa_verify(context, &ecdsaSignature, Array(digest), &publicKey).boolValue
    }
}

// MARK: - secp256k1.Signing.PublicKey + DataValidator

extension secp256k1.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the secp256k1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature(_ signature: secp256k1.Signing.ECDSASignature, for data: some DataProtocol) -> Bool {
        isValidSignature(signature, for: SHA256.hash(data: data))
    }
}
