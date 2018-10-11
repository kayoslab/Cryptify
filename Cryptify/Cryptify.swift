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

/// Basic public interface of the Cryptify framework.
@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) public class Cryptify {
    let keyStore = try? KeyStore(with: "tag")
    /// Singleton interface of the Cryptify framework to prevent
    /// any concurrent usage of the Key generation.
    public static var shared: Cryptify = .init()
    
    /// Private initialiser to actively hide it from the interface,
    /// since this class will solely be a singleton implementation.
    private init() { }
    
    public func generateForKeychain(with tag: String, type: KeyType = .ECSECRandom, keyLength length: Int = 256) throws {
        try keyStore?.generateForKeychain(with: type, keyLength: length)
    }
    
    public func generateForEnclave(with tag: String) throws {
        try keyStore?.generateForEnclave()
    }
    
    public func deletePublicKey() throws {
        try keyStore?.delete()
    }
    
    public func getPublicKey() throws {
        let pub = try keyStore?.retrieve()
        dump(pub)
    }
}
