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
    private let tagData: Data
    
    /// Initialise a Key
    init(with tag: String) throws {
        // Be sure that you don’t generate multiple, identically tagged keys.
        // These are difficult to tell apart during retrieval, unless they differ in some other,
        // searchable characteristic. Instead, use a unique tag for each key generation operation,
        // or delete old keys with a given tag.
        guard tag.count > 0, let tagData = tag.data(using: .utf8) else { throw KeyGenerationError.malformedTag }
        
        self.tagData = tagData
    }
    
    /// Generates a private key that is stored into the keychain. While doing this any other
    /// private key with the same tag is deleted from the keychain to prevent double entries
    /// and cluttering the keychain.
    ///
    /// - Parameters:
    ///   - type: The KeyType specifies the algorithm which is used for the key generation.
    ///           The current default is Eliptic Curves.
    ///   - length: The key's length. Please always provide a length when changing the keyType.
    ///             The default length is 256, since this is the maximum key length for the
    ///             Eliptic Curves type.
    /// - Throws: Can throw a KeyGenerationError or any suitable error instance on a failing
    ///           random key generation when thrown by `SecKeyCreateRandomKey`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    func generateForKeychain(with type: KeyType = .ECSECRandom, keyLength length: Int = 256) throws {
        // Verify that the max key length is not reached
        guard length > 0, length <= type.maxKeyLength() else { throw KeyGenerationError.malformedKeyLength }
        
        // Delete an already existing private key with the same identifier before safely creating
        // a new key. This prevents cluttering the keychain with double entries and reduces
        // the possible errors when fetching a key with a given tag.
        try delete()
        
        // Setting up the attributes for the key generation.
        let privateKeyAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
                                                   kSecAttrApplicationTag as String: tagData]
        let attributes: [String: Any] = [kSecAttrType as String: type.attribute(),
                                        kSecAttrKeySizeInBits as String: length,
                                        kSecPrivateKeyAttrs as String: privateKeyAttributes]
        
        try create(with: attributes)
    }
    
    /// Generates a private key that is stored into the secure enclave. While doing this any other
    /// private key with the same tag is deleted from the keychain to prevent double entries
    /// and cluttering the keychain.
    ///
    /// - Throws: Can throw a KeyGenerationError or any suitable error instance on a failing
    ///           random key generation when thrown by `SecKeyCreateRandomKey`. Consider the
    ///           Apple Security Framework documentation for non specified errors thrown within
    ///           this function.
    func generateForEnclave() throws {
        // Delete an already existing private key with the same identifier before safely creating
        // a new key. This prevents cluttering the keychain with double entries and reduces
        // the possible errors when fetching a key with a given tag.
        try delete()
        
        // Setting up the attributes for the key generation.
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) else {
            guard let error = error else { throw KeyGenerationError.unexpectedAccessControlNil }
            throw error.takeRetainedValue() as Error
        }
        let privateKeyAttributes: [String: Any] = [kSecAttrIsPermanent as String: true,
                                                   kSecAttrAccessControl as String: access,
                                                   kSecAttrApplicationTag as String: tagData]
        let attributes: [String: Any] = [kSecAttrType as String: KeyType.ECSECRandom.attribute(),
                                         kSecAttrKeySizeInBits as String: 256,
                                         kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                         kSecPrivateKeyAttrs as String: privateKeyAttributes]
        
        try create(with: attributes)
    }
    
    /// Try to create a private key with the given attributes. If the function fails to create a key,
    /// as indicated by a NULL return value, it fills in the error parameter to indicate the reason for failure.
    /// Otherwise, the key reference points to a new private key that’s ready for use.
    /// The key is also stored in the default keychain, from where you can read it later.
    ///
    /// - Parameter attributes: A dictionary you use to specify the attributes of the keys to be generated.
    /// - Throws: Can throw an unexpectedPrivateKeyNil error or any suitable error instance on failing.
    ///           Consider the Apple Security Framework documentation for non specified errors thrown
    ///           within this function.
    private func create(with attributes: [String: Any]) throws {
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            guard let error = error else { throw KeyGenerationError.unexpectedPrivateKeyNil }
            throw error.takeRetainedValue() as Error
        }
    }
    
    /// Deletes a private key that is stored into the secure enclave or the keychain.
    ///
    /// - Throws: Can throw a KeyGenerationError if an unexpected deletion status is reached.
    func delete() throws {
        let secDeleteQuery: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                             kSecReturnRef as String: true]
        let deletionStatus = SecItemDelete(secDeleteQuery as CFDictionary)
        guard deletionStatus == errSecSuccess || deletionStatus == errSecItemNotFound else {
            throw KeyGenerationError.unexpectedDeletionStatus(with: deletionStatus)
        }
    }
    
    func retrieve() throws -> SecKey? {
        var privateKey: CFTypeRef?
        let secDeleteQuery: [String: Any] = [kSecAttrApplicationTag as String: tagData,
                                             kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                             kSecReturnRef as String: true]
        
        let status = SecItemCopyMatching(secDeleteQuery as CFDictionary, &privateKey)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw KeyGenerationError.unexpectedRetriveStatus(with: status) }

        // I hate force unwrapping this, but since this is a CoreFoundation downcast
        // conditional downcasting always succeeds and therefore doesn't work here.
        // Let's prey this changes within upcoming swift versions.
        let publicKey = SecKeyCopyPublicKey(privateKey as! SecKey)
        return publicKey
    }
}
