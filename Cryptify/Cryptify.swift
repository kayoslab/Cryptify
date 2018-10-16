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
    /// Singleton interface of the Cryptify framework to prevent
    /// any concurrent usage of the Key generation.
    public static var shared: Cryptify = .init()
    
    /// Private initialiser to actively hide it from the interface,
    /// since this class will solely be a singleton implementation.
    private init() { }
    
    public func generateKey(with tag: String, type: KeyType = .ECSECRandom, keyLength length: Int = 256) throws {
        try KeyStore.generatePrivateKeyForKeychain(with: tag)
    }
    
    public func encryptDecryptTest(with tag: String) throws {
        let publicKey = try KeyStore.generateRawPublicKeyForPrivateKey(with: tag)

        guard let data = lorem.data(using: .utf8),
                let encryptedData = try Cryptor.encrypt(data: data, with: publicKey ?? "", tag: tag) else {
                    print("The encryption raised an error, please investigate")
                    return
        }
        
        guard let decryptedData = try Cryptor.decrypt(cipherText: encryptedData, tag: tag),
                let plainText = String(data: decryptedData, encoding: .utf8) else {
                    print("The decryption raised an error, please investigate")
                    return
        }
        
        print("The data was succesfully encrypted and decrypted.")
        if lorem == plainText {
            print("Everything worked fine! ✅")
        } else {
            print("Something went wrong! ⚠️")
        }
    }
}

/// An example string for general usage
private let lorem: String = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent sodales accumsan lorem, at porttitor sapien venenatis non. Phasellus mollis tincidunt purus at fermentum. Sed posuere mi at felis finibus, eget luctus turpis aliquam. Donec condimentum convallis tellus, at lacinia quam placerat quis. Nunc lectus orci, egestas eu rhoncus a, fringilla ut diam. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec vehicula tempor eleifend. Aenean turpis tortor, facilisis nec iaculis et, suscipit quis massa. Curabitur vitae euismod dui, et accumsan nibh. In hac habitasse platea dictumst. Curabitur finibus ut risus in venenatis."
