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

public enum KeyStoreError: Error {
    /// Please check the given key length. It might exceed the
    /// boundaries for the specified key type.
    case malformedKeyLength
    /// Please check the given tag. It might be malformed or empty.
    /// This error is raised when trying to create a data object
    /// by using the UTF-8 encoding. Usually this is due to an empty
    /// tag string.
    case malformedTag
    /// When deleting an existing key, this can possibly fail due to
    /// different reasons (e.g. missing permissions, missing disk space).
    /// If this happens, this error is raised, containing the exact status
    /// why this happened. Check for the OSStatus for clarification.
    case unexpectedDeletionStatus(with: OSStatus)
    /// When storing a new key, this can possibly fail due to
    /// different reasons (e.g. missing permissions, missing disk space).
    /// If this happens, this error is raised, containing the exact status
    /// why this happened. Check for the OSStatus for clarification.
    case unexpectedCreationStatus(with: OSStatus)
    /// When retriving an existing key, this can possibly fail due to
    /// different reasons (e.g. missing permissions, missing disk space).
    /// If this happens, this error is raised, containing the exact status
    /// why this happened. Check for the OSStatus for clarification.
    case unexpectedRetriveStatus(with: OSStatus)
    /// The system returned nil while trying to generate a access control
    /// object without throwing a reasonable error. This should not happen
    /// and seems to be rather weird. Please try to raise a bug with some
    /// reasonable information about your environment. Thank you.
    case unexpectedAccessControlNil
    /// The system returned nil while trying to generate a private key
    /// without throwing a reasonable error. This should not happen and
    /// seems to be rather weird. Please try to raise a bug with some
    /// reasonable information about your environment. Thank you.
    case unexpectedPrivateKeyNil
    /// The system returned nil while trying to generate a public key
    /// without throwing a reasonable error. This should not happen and
    /// seems to be rather weird. Please try to raise a bug with some
    /// reasonable information about your environment. Thank you.
    case unexpectedPublicKeyNil
}

public enum CryptorError: Error {
    /// An error occured while trying to retrive a public key with a
    /// specified tag. Either the tag was not correct, the key wasn't
    /// stored into the keychain properly or something else went wrong.
    case publicKeyRetriveError
    /// An error occured while trying to retrive a private key with a
    /// specified tag. Either the tag was not correct, the key wasn't
    /// stored into the keychain properly or something else went wrong.
    case privateKeyRetriveError
    /// The given algorithm, specified for encryption / decryption is
    /// not supported by the current device. Please specify a different
    /// algorithm.
    case unsupportedAlgorithm
    /// The length of the given data is not supported. This might happen
    /// du to a missing splitting before running the encryption process.
    /// Please check the input data.
    case unsupportedLength
    /// The system returned nil while trying to encrypt the given data
    /// without throwing a reasonable error. This should not happen and
    /// seems to be rather weird. Please try to raise a bug with some
    /// reasonable information about your environment. Thank you.
    case unexpectedDataEncryptionError
    /// The system returned nil while trying to decrypt the given data
    /// without throwing a reasonable error. This should not happen and
    /// seems to be rather weird. Please try to raise a bug with some
    /// reasonable information about your environment. Thank you.
    case unexpectedDataDecryptionError
}
