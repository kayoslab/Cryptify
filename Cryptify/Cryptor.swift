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
    
    
    /// Takes a given string object and tries to encrypt it for a specified asymetric communication partner.
    ///
    /// - Parameters:
    ///   - plainText: The plain data object, which is supposed to be encrypted.
    ///   - publicKey: The receipients public key if known (only neccessary if the public key is not yet stored into the keychain),
    ///                which is used for the cryptographic action. If specified this public key will be stored and associated with
    ///                the provided tag of the recipient.
    ///   - algorithm: The used SecKeyAlgorithm. The default is set to Eliptic curves with encryption
    ///                Standard X963 SHA256 AES GCM.
    ///   - tag: The recipients key tag, which can be used to retrieve a key from the keychain.
    ///   - type: Specifies the used key algorithm. The default (as specified in the key generation) is set to Eliptic curves.
    /// - Returns: Returns an encrypted Data object if possible.
    /// - Throws: Can throw an CryptorError or any suitable error instance on a failing
    ///           encryption when thrown by `SecKeyCreateEncryptedData`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    /// - Discussion: Due to block size limitations, that aren't yet implemented, this is currently not useable.
    @available(*, unavailable, message: "Due to block size limitations, that aren't yet implemented, this is currently not useable.Use encrypt(_:Data,tag:String) instead. ")
    static func encrypt(plainText: String, with publicKey: String? = nil, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = KeyTypeECSECRandom) throws -> Data? {
        guard let publicKey = try KeyStore.foreignPublicKey(with: publicKey, tag: tag, type: type) else {
            throw CryptorError.publicKeyRetriveError
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw CryptorError.unsupportedAlgorithm
        }
        guard plainText.count < SecKeyGetBlockSize(publicKey) else {
            throw CryptorError.unsupportedLength
        }

        var error: Unmanaged<CFError>?
        guard let plainTextData = plainText.data(using: .utf8) else { return nil }
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, algorithm, plainTextData as CFData, &error) as Data? else {
            guard let error = error else { throw CryptorError.unexpectedDataEncryptionError }
            throw error.takeRetainedValue() as Error
        }

        return cipherText
    }

    
    
    /// Takes a given data object and tries to encrypt it for a specified asymetric communication partner.
    ///
    /// - Parameters:
    ///   - data: The plain data object, which is supposed to be encrypted.
    ///   - publicKey: The receipients public key if known (only neccessary if the public key is not yet stored into the keychain),
    ///                which is used for the cryptographic action. If specified this public key will be stored and associated with
    ///                the provided tag of the recipient.
    ///   - algorithm: The used SecKeyAlgorithm. The default is set to Eliptic curves with encryption
    ///                Standard X963 SHA256 AES GCM.
    ///   - tag: The recipients key tag, which can be used to retrieve a key from the keychain.
    ///   - type: Specifies the used key algorithm. The default (as specified in the key generation) is set to Eliptic curves.
    /// - Returns: Returns an encrypted Data object if possible.
    /// - Throws: Can throw an CryptorError or any suitable error instance on a failing
    ///           encryption when thrown by `SecKeyCreateEncryptedData`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    static func encrypt(data: Data, with publicKey: String? = nil, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = KeyTypeECSECRandom) throws -> Data? {
        guard let publicKey = try KeyStore.foreignPublicKey(with: publicKey, tag: tag, type: type) else {
            throw CryptorError.publicKeyRetriveError
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw CryptorError.unsupportedAlgorithm
        }
        
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            guard let error = error else { throw CryptorError.unexpectedDataEncryptionError }
            throw error.takeRetainedValue() as Error
        }
        
        return data as Data
    }

    
    /// Takes a given data object and tries to decrypt it for a specified asymetric communication.
    ///
    /// - Parameters:
    ///   - cipherText: The secured data object which is meant to be decrypted.
    ///   - algorithm: The used SecKeyAlgorithm. The default is set to Eliptic curves with encryption
    ///                Standard X963 SHA256 AES GCM.
    ///   - tag: The decryptor's key tag, which can be used to retrieve a key from the keychain.
    ///   - type: Specifies the used key algorithm. The default (as specified in the key generation) is set to Eliptic curves.
    /// - Returns: The plain data object, which is the result of the encryption process.
    /// - Throws: Can throw an CryptorError or any suitable error instance on a failing
    ///           encryption when thrown by `SecKeyCreateDecryptedData`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    static func decrypt(cipherText: Data, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType = KeyTypeECSECRandom) throws -> Data? {
        guard let privateKey = try KeyStore.retrivePrivateKey(with: tag) else {
            throw CryptorError.privateKeyRetriveError
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw CryptorError.unsupportedAlgorithm
        }
        
        var error: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, algorithm, cipherText as CFData, &error) as Data? else {
            guard let error = error else { throw CryptorError.unexpectedDataDecryptionError }
            throw error.takeRetainedValue() as Error
        }
        
        return plainText
    }
}
