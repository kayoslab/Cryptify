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

@available(iOS 2.0, watchOS 2.0, tvOS 9.0, *) public enum KeyGenerationError: Error {
    
    case malformedKeyLength
    /// Please check the given tag. It might be malformed or empty.
    /// This error is raised when trying to create a data object
    /// by using the UTF-8 encoding. Usually this is due to an empty
    /// tag string.
    case malformedTag
    
    case unexpectedRetriveStatus(with: OSStatus)
    /// When creating a new Private key for a given tag, any existing key
    /// with the same tag will be deleted. This can possibly fail due to
    /// different reasons (e.g. missing permissions, missing disk space).
    /// If this happens, this error is raised, containing the exact status
    /// why this happened. Check for the OSStatus for clarification.
    case unexpectedDeletionStatus(with: OSStatus)
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
}
