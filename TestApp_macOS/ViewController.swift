//
//  ViewController.swift
//  TestApp_macOS
//
//  Created by Simon Krüger on 19.10.18.
//  Copyright © 2018 cr0ss. All rights reserved.
//

import Cocoa
import Cryptify_macOS

class ViewController: NSViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
        
        // Do any additional setup after loading the view, typically from a nib.
        do {
            let cryptify = Cryptify(with: KeyTypeRSA)
            try cryptify.generateKey(with: "ExampleGroup.ExampleTag.ExampleUser", keyLength: 2048)
            try cryptify.encryptDecryptTest(with: "ExampleGroup.ExampleTag.ExampleUser")
        } catch {
            dump(error)
        }
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

