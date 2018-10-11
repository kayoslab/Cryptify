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

class Encryptor {
    func encrypt(data: Data, with publicKey: String, algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, tag: String, type: KeyType) throws -> CFData? {
        guard let publicKey = try KeyStore.foreignPublicKey(with: publicKey, tag: tag, type: type) else { return nil }
        
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) else {
            guard let error = error else { throw KeyStoreError.unexpectedAccessControlNil }
            throw error.takeRetainedValue() as Error
        }
        
        return data
    }
}
