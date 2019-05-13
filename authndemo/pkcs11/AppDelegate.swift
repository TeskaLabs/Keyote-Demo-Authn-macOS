//
//  AppDelegate.swift
//  authndemo
//
//  Created by Ales Teska on 10.5.19.
//  Copyright © 2019 TeskaLabs. All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    var pkcs11:PKCS11! = try! PKCS11()
    
    func applicationDidFinishLaunching(_ aNotification: Notification) {
    }

    
    func applicationWillTerminate(_ aNotification: Notification) {
        pkcs11 = nil
    }

}
