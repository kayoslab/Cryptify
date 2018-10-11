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

import UIKit
import Cryptify

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        do {
//            try Cryptify.shared.generateForKeychain(with: "test", type: .RSA, keyLength: 8192)
//            try Cryptify.shared.generateForEnclave(with: "test")
//            try Cryptify.shared.deletePublicKey()
//            try Cryptify.shared.getPublicKey()
        } catch {
            dump(error)
        }
    }


}

