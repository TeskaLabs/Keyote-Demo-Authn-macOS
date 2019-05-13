//
//  ViewController.swift
//  authndemo
//
//  Created by Ales Teska on 10.5.19.
//  Copyright © 2019 TeskaLabs. All rights reserved.
//

import Cocoa

class KeyoteLoginViewController: NSViewController {

    @IBOutlet weak var labelTF: NSTextFieldCell!
    @IBOutlet weak var progressBar: NSProgressIndicator!

    var slotList:[CK_SLOT_ID] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        
        
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    override func viewDidAppear() {
        refreshSlots()
    }
    
    private func refreshSlots() {
        //TODO: Refresh this ...
        let appDelegate = NSApplication.shared.delegate as! AppDelegate
        do {
            slotList = try appDelegate.pkcs11.getSlotList(tokenPresent: true)
        } catch {
            slotList = []
        }

        if slotList.count == 0 {
            labelTF.title = "Start the Keyote app!"
        } else {
            labelTF.title = ""
        }
    }
    
    @IBAction func onKeyoteClick(_ sender: Any) {
        
        if slotList.count == 0 { return }
        let appDelegate = NSApplication.shared.delegate as! AppDelegate
        progressBar.startAnimation(self)
        
        DispatchQueue.global(qos: .background).async {
            defer {
                DispatchQueue.main.async {
                    self.progressBar.stopAnimation(self)
                }
            }
            do {
                let session = try appDelegate.pkcs11.openSession(slotID: self.slotList[0], flags: CKF_SERIAL_SESSION)
                let objectHandles = try session.findObjects(template: [
                    PKCS11Attribute(objectClass: CKO_PRIVATE_KEY),
                    PKCS11Attribute(keyType: CKK_RSA)
                ])
                
                if objectHandles.count == 0 { return }
                
                try session.signInit(mechanismType: CKM_SHA1_RSA_PKCS, hKey: objectHandles[0])
                var data = Data.init(capacity: 10)
                let _ = try session.sign(data: &data)
            }
            catch {
                return
            }
            
            DispatchQueue.main.async {
                self.dismiss(self)
            }
        }
    }
}
