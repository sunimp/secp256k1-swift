//
//  SubjectPublicKeyInfo.swift
//  GigaBitcoin/secp256k1.swift
//
//  Modifications Copyright (c) 2023 GigaBitcoin LLC
//  Distributed under the MIT software license
//
//  See the accompanying file LICENSE for information
//
//
//  NOTICE: THIS FILE HAS BEEN MODIFIED BY GigaBitcoin LLC
//  UNDER COMPLIANCE WITH THE APACHE 2.0 LICENSE FROM THE
//  ORIGINAL WORK OF THE COMPANY Apple Inc.
//
//  THE FOLLOWING IS THE COPYRIGHT OF THE ORIGINAL DOCUMENT:
//
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

extension ASN1 {
    struct SubjectPublicKeyInfo: ASN1ImplicitlyTaggable {
        // MARK: Static Computed Properties

        static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        // MARK: Properties

        var algorithmIdentifier: RFC5480AlgorithmIdentifier

        var key: ASN1.ASN1BitString

        // MARK: Lifecycle

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            // The SPKI block looks like this:
            //
            // SubjectPublicKeyInfo  ::=  SEQUENCE  {
            //   algorithm         AlgorithmIdentifier,
            //   subjectPublicKey  BIT STRING
            // }
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let algorithmIdentifier = try ASN1.RFC5480AlgorithmIdentifier(asn1Encoded: &nodes)
                let key = try ASN1.ASN1BitString(asn1Encoded: &nodes)

                return Self(algorithmIdentifier: algorithmIdentifier, key: key)
            }
        }

        init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: [UInt8]) {
            self.algorithmIdentifier = algorithmIdentifier
            self.key = ASN1BitString(bytes: key[...])
        }

        private init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: ASN1.ASN1BitString) {
            self.algorithmIdentifier = algorithmIdentifier
            self.key = key
        }

        // MARK: Functions

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(algorithmIdentifier)
                try coder.serialize(key)
            }
        }
    }

    struct RFC5480AlgorithmIdentifier: ASN1ImplicitlyTaggable, Hashable {
        // MARK: Static Computed Properties

        static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        // MARK: Properties

        var algorithm: ASN1.ASN1ObjectIdentifier

        var parameters: ASN1.ASN1Any?

        // MARK: Lifecycle

        init(algorithm: ASN1.ASN1ObjectIdentifier, parameters: ASN1.ASN1Any?) {
            self.algorithm = algorithm
            self.parameters = parameters
        }

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            // The AlgorithmIdentifier block looks like this.
            //
            // AlgorithmIdentifier  ::=  SEQUENCE  {
            //   algorithm   OBJECT IDENTIFIER,
            //   parameters  ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // ECParameters ::= CHOICE {
            //   namedCurve         OBJECT IDENTIFIER
            //   -- implicitCurve   NULL
            //   -- specifiedCurve  SpecifiedECDomain
            // }
            //
            // We don't bother with helpers: we just try to decode it directly.
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let algorithmOID = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)

                let parameters = nodes.next().map { ASN1.ASN1Any(asn1Encoded: $0) }

                return .init(algorithm: algorithmOID, parameters: parameters)
            }
        }

        // MARK: Functions

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(algorithm)
                if let parameters {
                    try coder.serialize(parameters)
                }
            }
        }
    }
}

// MARK: Algorithm Identifier Statics

extension ASN1.RFC5480AlgorithmIdentifier {
    static let ecdsaP256K1 = ASN1.RFC5480AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1.ASN1ObjectIdentifier.NamedCurves.secp256k1)
    )
}

#endif // Linux or !SwiftPM
