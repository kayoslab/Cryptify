/*
 *
 * Copyright (C) Simon C. Krüger - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Simon C. Krüger and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Simon C.Krüger
 * and its suppliers and are protected by trade secret or copyright law.
 *
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from the owner.
 *
 * Written by Simon C. Krüger <dev@cr0ss.org>, 10.10.2018
 *
 */

import Foundation
import Security

/// Elliptic curve algorithm - ECC requires smaller keys
/// compared to non-EC cryptography  to provide equivalent security.
@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) public let KeyTypeECSECRandom = KeyType(with: "ECSECRandom", maxLength: 256, stringAttribute: kSecAttrKeyTypeECSECPrimeRandom)

/// RSA algorithm - it is one of the first public-key cryptosystems
/// and is widely used for secure data transmission.
/// - Discussion: The ECC generation with `KeyTypeECSECRandom` can be
///               much faster in comparison to RSA on iOS due to the
///               smaller key size.
@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) public let KeyTypeRSA = KeyType(with: "RSA", maxLength: 8192, stringAttribute: kSecAttrKeyTypeRSA)

/// A key type specifies an algorithm that is used when generating a
/// new key for the keychain. This affects the necessary time for
/// generation as well as the time which is needed to transfer the
/// key and the encryption / decryption. For your application,
/// specify one keytype, that is used all over the environment.
public struct KeyType {
    public var name: String
    /// Use this to check if the specified key length is not reaching
    /// the system's boundaries for maximum key lenth. This is currently
    /// hardcoded, even though you'd expect this to be available via an
    /// API. WHY?
    var maxKeyLength: Int
    /// Retreive the necessary CFString from the Security framework
    /// to create attribute dictionary in the key generation process.
    var attribute: CFString
    
    init(with rawName: String, maxLength: Int, stringAttribute: CFString) {
        name = rawName
        maxKeyLength = maxLength
        attribute = stringAttribute
    }
}
