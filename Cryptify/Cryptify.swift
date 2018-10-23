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

/// Basic public interface of the Cryptify framework. You should keep
/// a singleton reference on this class so that you can ensure to always
/// use the same KeyType for encryption / decryption / key handling.
public class Cryptify {
    private let keyType: KeyType
    
    /// Basic public interface of the Cryptify framework. You should keep
    /// a singleton reference on this class so that you can ensure to always
    /// use the same KeyType for encryption / decryption / key handling.
    ///
    /// - Parameters:
    ///   - keyType: The specified algorithm that should be used for the key
    ///              generation and handling.
    public init(with keyType: KeyType) {
        self.keyType = keyType
    }
    
    public func generateKey(with tag: String, keyLength: Int) throws {
        try KeyStore.generatePrivateKeyForKeychain(with: tag, type: keyType, keyLength: keyLength)
        print("Key generation finished 🔑")
    }
    
    public func encryptDecryptTest(with tag: String) throws {
        let publicKey = try KeyStore.generateRawPublicKeyForPrivateKey(with: tag)

        guard let data = lorem.data(using: .utf8),
            let encryptedData = try Cryptor.encrypt(data: data,
                                                    with: publicKey ?? "",
                                                    tag: "ExampleGroup.ExampleTag.ExampleRecipient",
                                                    type: keyType) else {
                return
        }
        
        guard let decryptedData = try Cryptor.decrypt(cipherText: encryptedData,
                                                      tag: tag,
                                                      type: keyType),
                let plainText = String(data: decryptedData, encoding: .utf8) else {
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
