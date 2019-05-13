//
//  MainViewController.swift
//  authndemo
//
//  Created by Ales Teska on 11.5.19.
//  Copyright © 2019 TeskaLabs. All rights reserved.
//

import Cocoa

class MainViewController: NSViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
    }
    
    override func viewDidAppear() {
        let storyBoard: NSStoryboard = NSStoryboard(name: "Main", bundle: nil)
        guard let loginViewController = storyBoard.instantiateController(withIdentifier: "keyoteLoginViewController") as? NSViewController else {
            return
        }
        presentAsModalWindow(loginViewController)
    }
}
