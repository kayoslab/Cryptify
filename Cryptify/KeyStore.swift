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

@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) class KeyStore {
    
    /// Generates a private key that is stored into the keychain. While doing this any other
    /// private key with the same tag is deleted from the keychain to prevent double entries
    /// and cluttering the keychain.
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which is used to store the private key into the keychain.
    ///          This identifier will later be used to refetch the key for encryption/decryption.
    ///          Always use a readable identifier, so that a cluttering of the keychain can be
    ///          prevented and keys are not deleted unintentionally.
    ///   - type: The KeyType specifies the algorithm which is used for the key generation.
    ///           The current default is Eliptic Curves.
    ///   - length: The key's length. Please always provide a length when changing the keyType.
    ///             The default length is 256, since this is the maximum key length for the
    ///             Eliptic Curves type.
    /// - Throws: Can throw a KeyStoreError or any suitable error instance on a failing
    ///           random key generation when thrown by `SecKeyCreateRandomKey`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    static func generatePrivateKeyForKeychain(with tag: String, type: KeyType = .ECSECRandom, keyLength length: Int = 256) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        // Verify that the max key length is not reached
        guard length > 0, length <= type.maxKeyLength() else { throw KeyStoreError.malformedKeyLength }
        
        // Delete an already existing private key with the same identifier before safely creating
        // a new key. This prevents cluttering the keychain with double entries and reduces
        // the possible errors when fetching a key with a given tag.
        try KeyStore.deletePrivateKey(with: tag)
        
        // Setting up the attributes for the key generation.
        let privateKeyAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
                                                   kSecAttrApplicationTag as String: tagData]
        let attributes: [String: Any] = [kSecAttrType as String: type.attribute(),
                                        kSecAttrKeySizeInBits as String: length,
                                        kSecPrivateKeyAttrs as String: privateKeyAttributes]
        
        try KeyStore.createPrivateKey(with: attributes)
    }
    
    
    /// Generates a private key that is stored into the secure enclave. While doing this any other
    /// private key with the same tag is deleted from the keychain to prevent double entries
    /// and cluttering the keychain.
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which is used to store the private key into the keychain.
    ///          This identifier will later be used to refetch the key for encryption/decryption.
    ///          Always use a readable identifier, so that a cluttering of the keychain can be
    ///          prevented and keys are not deleted unintentionally.
    /// - Throws: Can throw a KeyStoreError or any suitable error instance on a failing
    ///           random key generation when thrown by `SecKeyCreateRandomKey`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    static func generatePrivateKeyForEnclave(with tag: String) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        // Delete an already existing private key with the same identifier before safely creating
        // a new key. This prevents cluttering the keychain with double entries and reduces
        // the possible errors when fetching a key with a given tag.
        try KeyStore.deletePrivateKey(with: tag)
        
        // Setting up the attributes for the key generation.
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
            guard let error = error else { throw KeyStoreError.unexpectedAccessControlNil }
            throw error.takeRetainedValue() as Error
        }
        let privateKeyAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
                                                   kSecAttrAccessControl as String: access,
                                                   kSecAttrApplicationTag as String: tagData]
        let attributes: [String: Any] = [kSecAttrType as String: KeyType.ECSECRandom.attribute(),
                                         kSecAttrKeySizeInBits as String: 256,
                                         kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                         kSecPrivateKeyAttrs as String: privateKeyAttributes]
        
        try KeyStore.createPrivateKey(with: attributes)
    }
    
    
    /// Try to create a private key with the given attributes. If the function fails to create a key,
    /// as indicated by a NULL return value, it fills in the error parameter to indicate the reason for failure.
    /// Otherwise, the key reference points to a new private key that’s ready for use.
    /// The key is also stored in the default keychain, from where you can read it later.
    ///
    /// - Parameters
    ///   - attributes: A dictionary you use to specify the attributes of the keys to be generated.
    /// - Throws: Can throw an unexpectedPrivateKeyNil error or any suitable error instance on failing.
    ///           Consider the Apple Security Framework documentation for non specified errors thrown
    ///           within this function.
    private static func createPrivateKey(with attributes: [String: Any]) throws {
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            guard let error = error else { throw KeyStoreError.unexpectedPrivateKeyNil }
            throw error.takeRetainedValue() as Error
        }
    }
    

    /// Deletes a private key that is stored into the secure enclave or the keychain.
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which was used to store the private key into the keychain.
    /// - Throws: Can throw a KeyStoreError if an unexpected deletion status is reached or the
    ///           Provided tag is malformed.
    private static func deletePrivateKey(with tag: String) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        let secDeleteQuery: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                             kSecReturnRef as String: true]
        let deletionStatus = SecItemDelete(secDeleteQuery as CFDictionary)
        guard deletionStatus == errSecSuccess || deletionStatus == errSecItemNotFound else {
            throw KeyStoreError.unexpectedDeletionStatus(with: deletionStatus)
        }
    }
    
    
    /// Retrives an optional public key reference to a stored private key from the keychain
    /// by using the tag as a unique identifier
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which was used to store the private key into the keychain.
    /// - Returns: A reference to a public key if possible. If the key could not be found with
    ///            the given tag, the function returns nil.
    /// - Throws: Can throw a KeyStoreError if an unexpected retrive status is reached or the
    ///           Provided tag is malformed.
    static func generatePublicKeyForPrivateKey(with tag: String) throws -> SecKey? {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        var privateKey: CFTypeRef?
        let retrieveQuerry: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                             kSecReturnRef as String: true]
        
        let status = SecItemCopyMatching(retrieveQuerry as CFDictionary, &privateKey)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw KeyStoreError.unexpectedRetriveStatus(with: status) }

        // I hate force unwrapping this, but since this is a CoreFoundation downcast
        // conditional downcasting always succeeds and therefore doesn't work here.
        // Let's prey this changes within upcoming swift versions.
        let publicKey = SecKeyCopyPublicKey(privateKey as! SecKey)
        return publicKey
    }
    
    
    /// Retrives an optional string representation of a stored private key from the keychain
    /// by using the tag as a unique identifier
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which was used to store the private key into the keychain.
    /// - Returns: A representation of a public key if possible. If the key could not be found
    ///            with the given tag, the function returns nil.
    /// - Throws: Can throw a KeyStoreError if an unexpected retrive status is reached or the
    ///           Provided tag is malformed.
    static func generateRawPublicKeyForPrivateKey(with tag: String) throws -> String? {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        var privateKey: CFTypeRef?
        let retrieveQuerry: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                             kSecReturnRef as String: true]
        
        let status = SecItemCopyMatching(retrieveQuerry as CFDictionary, &privateKey)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw KeyStoreError.unexpectedRetriveStatus(with: status) }
        
        // I hate force unwrapping this, but since this is a CoreFoundation downcast
        // conditional downcasting always succeeds and therefore doesn't work here.
        // Let's prey this changes within upcoming swift versions.
        guard let publicKey = SecKeyCopyPublicKey(privateKey as! SecKey) else { return nil }
        
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            guard let error = error else { throw KeyStoreError.unexpectedPublicKeyNil }
            throw error.takeRetainedValue() as Error
        }
        
        return (data as Data).base64EncodedString()
    }
    
}

extension KeyStore {
    
    
    /// Stores a foreign public key into the Keychain and returns the necessary reference to the SecKey.
    /// This helps to work with any type of encryption that bases on a public key which is received
    /// from an external party. This might return nil, if the specified type and the actual key type
    /// don't match.
    ///
    /// - Parameters:
    ///   - key: The raw String representation of a Public Key.
    ///   - tag: The tag which is used to store the Public Key in the keychain. This should contain
    ///          a useful description, so that the key can relate to the application aswell
    ///          as to the party with whom the communication will be established.
    /// - Returns: An optional reference to a public key stored into the keychain.
    /// - Throws: Can throw a KeyStoreError or any suitable error instance on a failing
    ///           random key generation when thrown by `SecKeyCreateRandomKey`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    static func foreignPublicKey(with key: String, tag: String, type: KeyType = .ECSECRandom) throws -> SecKey? {
        try KeyStore.storeForeignPublicKey(key: key, with: tag, type: type)
        let retrive = try KeyStore.retrieveForeignPublicKey(with: tag, type: type)
        
        return retrive
    }
    
    
    
    /// Deletes a public key that is stored into the keychain.
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which was used to store the public key into the keychain.
    /// - Throws: Can throw a KeyStoreError if an unexpected deletion status is reached or the
    ///           Provided tag is malformed.
    private static func deleteForeignPublicKey(with tag: String) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        let secDeleteQuery: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                             kSecReturnRef as String: true]
        
        let deletionStatus = SecItemDelete(secDeleteQuery as CFDictionary)
        guard deletionStatus == errSecSuccess || deletionStatus == errSecItemNotFound else {
            throw KeyStoreError.unexpectedDeletionStatus(with: deletionStatus)
        }
    }
    
    
    
    /// Stores a foreign public key into the Keychain, so that an instantiation from a String
    /// object can be achieved. While doing this any other public key with the same tag is
    /// deleted from the keychain to prevent double entries and cluttering the keychain.
    ///
    /// - Parameters:
    ///   - key: A string value of the public key that should be stored into the keychain.
    ///   - tag: A unique identifier which will be used to store the public key into the keychain.
    ///   - type: The KeyType specifies the algorithm which is used for the key generation.
    ///           The current default is Eliptic Curves.
    /// - Throws: Can throw a KeyStoreError in case an unexpected creation status occurs
    ///           while trying to add the public key.
    private static func storeForeignPublicKey(key: String, with tag: String, type: KeyType = .ECSECRandom) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        guard let keyData = Data(base64Encoded: key) else { return }
        
        // Delete an already existing private key with the same identifier before safely creating
        // a new key. This prevents cluttering the keychain with double entries and reduces
        // the possible errors when fetching a key with a given tag.
        try KeyStore.deleteForeignPublicKey(with: tag)
        
        var queryFilter: [String : Any] = [kSecClass as String: kSecClassKey,
                                           kSecAttrApplicationTag as String: tagData,
                                           kSecValueData as String: keyData,
                                           kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                           kSecReturnPersistentRef as String: true]
        switch type {
            case .ECSECRandom: queryFilter[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
            case .RSA: queryFilter[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        }
        
        let creationStatus = SecItemAdd(queryFilter as CFDictionary, nil)
        
        guard creationStatus == noErr || creationStatus == errSecDuplicateItem else {
            throw KeyStoreError.unexpectedCreationStatus(with: creationStatus)
        }
    }
    
    
    /// Retrives a foreign public key from the Keychain
    ///
    /// - Parameters:
    ///   - tag: A unique identifier which will be used to retrive the public key from the keychain.
    ///   - type: The KeyType specifies the algorithm which is used for the key generation.
    ///           The current default is Eliptic Curves.
    /// - Throws: Can throw a KeyStoreError in case an unexpected retrive status occurs
    ///           while trying to fetch the public key.
    private static func retrieveForeignPublicKey(with tag: String, type: KeyType = .ECSECRandom) throws -> SecKey? {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyStoreError.malformedTag }
        
        var publicKeyRef: CFTypeRef?
        var queryFilter: [String : Any] = [kSecClass as String: kSecClassKey,
                                           kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                           kSecAttrApplicationTag as String: tagData,
                                           kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                           kSecReturnRef as String: true]
        switch type {
            case .ECSECRandom: queryFilter[kSecAttrKeyType as String] = kSecAttrKeyTypeECSECPrimeRandom
            case .RSA: queryFilter[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        }
        
        let status = SecItemCopyMatching(queryFilter as CFDictionary, &publicKeyRef)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw KeyStoreError.unexpectedRetriveStatus(with: status) }
        
        // I hate force unwrapping this, but since this is a CoreFoundation downcast
        // conditional downcasting always succeeds and therefore doesn't work here.
        // Let's prey this changes within upcoming swift versions and till then we
        // should at least ensure the KeyRef is not nil. This sometimes happens
        // when there's a mismatch between key and specified kSecAttrKeyType.
        guard publicKeyRef != nil else { return nil }
        guard let publicKey = SecKeyCopyPublicKey(publicKeyRef as! SecKey) else { return nil }
        
        return publicKey
    }
    
}
