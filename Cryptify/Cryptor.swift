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

class Cryptor {
    
    static func encrypt(plainText: String, with publicKey: String, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = .ECSECRandom) throws -> Data? {
        guard let publicKey = try KeyStore.foreignPublicKey(with: publicKey, tag: tag, type: type) else {
            throw EncryptionError.publicKeyError
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw EncryptionError.unsupportedAlgorithm
        }
        guard plainText.count < SecKeyGetBlockSize(publicKey) else {
            throw EncryptionError.unsupportedLength
        }
        
        var error: Unmanaged<CFError>?
        guard let plainTextData = plainText.data(using: .utf8) else { return nil }
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, algorithm, plainTextData as CFData, &error) as Data? else {
            guard let error = error else { throw EncryptionError.unexpectedDataEncryptionError }
            throw error.takeRetainedValue() as Error
        }
        
        return cipherText
    }
    
    
    static func encrypt(data: Data, with publicKey: String, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = .ECSECRandom) throws -> Data? {
        guard let publicKey = try KeyStore.foreignPublicKey(with: publicKey, tag: tag, type: type) else {
            throw EncryptionError.publicKeyError
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw EncryptionError.unsupportedAlgorithm
        }
        
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            guard let error = error else { throw EncryptionError.unexpectedDataEncryptionError }
            throw error.takeRetainedValue() as Error
        }
        
        return data as Data
    }

    
    static func decrypt(cipherText: Data, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = .ECSECRandom) throws -> Data? {
        guard let privateKey = try KeyStore.retrivePrivateKey(with: tag) else {
            throw EncryptionError.publicKeyError
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw EncryptionError.unsupportedAlgorithm
        }
        
        var error: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, algorithm, cipherText as CFData, &error) as Data? else {
            guard let error = error else { throw EncryptionError.unexpectedDataDecryptionError }
            throw error.takeRetainedValue() as Error
        }
        
        return plainText
    }
}
