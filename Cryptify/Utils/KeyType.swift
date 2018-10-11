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

/// Values you might use as a key type when creating a new Asymetric key.
@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) public enum KeyType {
    /// RSA algorithm.
    case RSA
    /// Elliptic curve algorithm.
    case ECSECRandom
    
    /// Retreive the necessary CFString from the Security framework
    /// to create attribute dictionary in the key generation process.
    func attribute() -> CFString {
        switch self {
            case .RSA: return kSecAttrKeyTypeRSA
            case .ECSECRandom: return kSecAttrKeyTypeECSECPrimeRandom
        }
    }
    
    func maxKeyLength() -> Int {
        switch self {
            case .RSA: return 8192
            case .ECSECRandom: return 256
        }
    }
}

