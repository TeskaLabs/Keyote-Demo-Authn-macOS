//
//  pkcs11.swift
//  authndemo
//
//  Created by Ales Teska on 11.5.19.
//  Copyright © 2019 TeskaLabs. All rights reserved.
//

import Foundation


enum PKCS11Error: Error {
    case failedLoadingLibrary
    case rv(rv: CK_RV, text: String)
}

class PKCS11 {
    
    let libHandle: UnsafeMutableRawPointer
    let functionList: CK_FUNCTION_LIST_PTR
    let null: UnsafeMutableRawPointer? = nil
    
    
    init() throws {
        var rv: CK_RV
        
        let dylibPath = "keyotepkcs11.so"
        guard let dl = dlopen(dylibPath, RTLD_NOW) else {
            throw PKCS11Error.failedLoadingLibrary
        }
        libHandle = dl
        

        // Call to C_Initialize
        guard let sym_i = dlsym(libHandle, "C_Initialize") else {
            dlclose(libHandle)
            throw PKCS11Error.failedLoadingLibrary
        }

        var initialize_args = CK_C_INITIALIZE_ARGS(
            CreateMutex: nil,
            DestroyMutex: nil,
            LockMutex: nil,
            UnlockMutex: nil,
            flags: 0,
            pReserved: nil
        )
        
        let f = unsafeBitCast(sym_i, to: C_Initialize.self)
        rv = f(&initialize_args)
        if (rv != CKR_OK) {
            dlclose(libHandle)
            throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) )
        }

        
        // Call to C_GetFunctionList
        guard let sym_gfl = dlsym(libHandle, "C_GetFunctionList") else {
            dlclose(libHandle)
            throw PKCS11Error.failedLoadingLibrary
        }

        var fk: CK_FUNCTION_LIST_PTR?
        let f_gfl = unsafeBitCast(sym_gfl, to: C_GetFunctionList.self)
        rv = f_gfl(&fk)
        if (rv != CKR_OK) {
            dlclose(libHandle)
            throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) )
        }
        if (fk == nil) {
            throw PKCS11Error.failedLoadingLibrary
        }

        functionList = fk!
    }
    
    
    deinit {
        _ = functionList.pointee.C_Finalize(null)

        dlclose(libHandle)
    }

    
    func getSlotList(tokenPresent: Bool) throws -> [CK_SLOT_ID] {
        var rv:CK_RV
        var ulCount:CK_ULONG = 0
        
        let tPresent: CK_BBOOL
        if tokenPresent { tPresent = CK_BBOOL(CK_TRUE) }
        else { tPresent = CK_BBOOL(CK_FALSE) }
        
        let slotListNull: UnsafeMutablePointer<CK_SLOT_ID>? = nil
        rv = functionList.pointee.C_GetSlotList?(tPresent, slotListNull, &ulCount) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }

        var slotList:[CK_SLOT_ID] = [CK_SLOT_ID](repeating: 0, count: Int(ulCount))
        if (ulCount > 0) { // Only if there are slots
            rv = functionList.pointee.C_GetSlotList?(tPresent, &slotList, &ulCount) ?? CKR_FUNCTION_NOT_SUPPORTED
            guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }
        }
        
        return slotList
    }
    
    func openSession(slotID: CK_SLOT_ID, flags: CK_FLAGS) throws -> PKCS11Session
    {
        var rv:CK_RV
        
        var hSession: CK_SESSION_HANDLE = 0
        let notifyNull: CK_NOTIFY? = nil
        rv = functionList.pointee.C_OpenSession?(slotID, flags, null, notifyNull, &hSession) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }

        return PKCS11Session(pkcs11: self, hSession: hSession)
    }
    
}


class PKCS11Session {
    let pkcs11: PKCS11
    let hSession: CK_SESSION_HANDLE
    
    init(pkcs11: PKCS11, hSession: CK_SESSION_HANDLE) {
        self.pkcs11 = pkcs11
        self.hSession = hSession
    }
    
    deinit {
        let _ = pkcs11.functionList.pointee.C_CloseSession(hSession)
    }

    
    func findObjects(template: [PKCS11Attribute]) throws -> [CK_OBJECT_HANDLE] {
        var rv: CK_RV
        // This is a temporary storage for the binary representation of attributes' values
        var templateData: [NSMutableData] = []
        
        var rTemplate = [CK_ATTRIBUTE].init(repeating: CK_ATTRIBUTE(type: 0, pValue: nil, ulValueLen: 0), count: template.count)
        for i in 0..<rTemplate.count {
            rTemplate[i].type = template[i].type
            
            template[i].value.withUnsafeMutableBytes{ (ptr:UnsafeMutableRawBufferPointer) -> Void in
                let template_data = NSMutableData.init(bytes: ptr.baseAddress, length: ptr.count)
                templateData.append(template_data)
                rTemplate[i].pValue = template_data.mutableBytes
                rTemplate[i].ulValueLen = CK_ULONG(ptr.count)
            }
        }

        rv = pkcs11.functionList.pointee.C_FindObjectsInit?(hSession, &rTemplate, CK_ULONG(rTemplate.count)) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }

        var ret:[CK_OBJECT_HANDLE] = []
        while true {
            var hObject: CK_OBJECT_HANDLE = CK_INVALID_HANDLE
            var ulObjectCount: CK_ULONG = 0

            rv = pkcs11.functionList.pointee.C_FindObjects?(hSession, &hObject, 1, &ulObjectCount) ?? CKR_FUNCTION_NOT_SUPPORTED
            guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }

            if (ulObjectCount == 0) { break }
            
            ret.append(hObject)
        }

        rv = pkcs11.functionList.pointee.C_FindObjectsFinal?(hSession) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }
        
        return ret
    }
    
    
    func signInit(mechanismType: CK_MECHANISM_TYPE, hKey: CK_OBJECT_HANDLE) throws {
        let null: UnsafeMutableRawPointer? = nil
        var mechanism = CK_MECHANISM(mechanism: mechanismType, pParameter: null, ulParameterLen: 0)
        let rv = pkcs11.functionList.pointee.C_SignInit?(hSession, &mechanism, hKey) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }
    }

    
    func sign(data: inout Data, signatureSize: Int = 1024) throws -> Data {
        
        let d = data.withUnsafeMutableBytes{ (ptr:UnsafeMutableRawBufferPointer) -> UnsafeMutablePointer<UInt8> in
            ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)
        }

        var signature = Data.init(capacity: signatureSize)
        let s = signature.withUnsafeMutableBytes{ (ptr:UnsafeMutableRawBufferPointer) -> UnsafeMutablePointer<UInt8> in
            ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)
        }

        var ulSignatureLen: CK_ULONG = CK_ULONG(signatureSize)
        let rv = pkcs11.functionList.pointee.C_Sign?(hSession, d, CK_ULONG(data.count), s, &ulSignatureLen) ?? CKR_FUNCTION_NOT_SUPPORTED
        guard rv == CKR_OK else { throw PKCS11Error.rv(rv: rv, text: PKCS11RVMap[rv] ?? String(format:"rv: 0x%08XUL", rv) ) }

        return signature
    }
    
}


class PKCS11Attribute {
    
    let type: CK_ATTRIBUTE_TYPE
    var value: Data

    init(type: CK_ATTRIBUTE_TYPE, data: Data) {
        self.type = type
        self.value = data
    }
    
    convenience init(objectClass: CK_OBJECT_CLASS) {
        let data:Data = PKCS11Attribute.toByteArray(objectClass.littleEndian)
        self.init(type: CKA_CLASS, data: data)
    }

    convenience init(keyType: CK_KEY_TYPE) {
        let data:Data = PKCS11Attribute.toByteArray(keyType.littleEndian)
        self.init(type: CKA_KEY_TYPE, data: data)
    }
    
    static private func toByteArray<T>(_ value: T) -> Data {
        var value = value
            let x = withUnsafeBytes(of: &value) { Array($0) }
        return Data(x)
    }

}


typealias C_Initialize = @convention(c) (CK_VOID_PTR) -> CK_RV
typealias C_GetFunctionList = @convention(c) (CK_FUNCTION_LIST_PTR_PTR) -> CK_RV

let PKCS11RVMap:[CK_RV: String] = [
    CKR_OK: "CKR_OK",
    CKR_CANCEL: "CKR_CANCEL",
    CKR_HOST_MEMORY: "CKR_HOST_MEMORY",
    CKR_SLOT_ID_INVALID: "CKR_SLOT_ID_INVALID",
    CKR_GENERAL_ERROR: "CKR_GENERAL_ERROR",
    CKR_FUNCTION_FAILED: "CKR_FUNCTION_FAILED",
    CKR_ARGUMENTS_BAD: "CKR_ARGUMENTS_BAD",
    CKR_NO_EVENT: "CKR_NO_EVENT",
    CKR_NEED_TO_CREATE_THREADS: "CKR_NEED_TO_CREATE_THREADS",
    CKR_CANT_LOCK: "CKR_CANT_LOCK",
    CKR_ATTRIBUTE_READ_ONLY: "CKR_ATTRIBUTE_READ_ONLY",
    CKR_ATTRIBUTE_SENSITIVE: "CKR_ATTRIBUTE_SENSITIVE",
    CKR_ATTRIBUTE_TYPE_INVALID: "CKR_ATTRIBUTE_TYPE_INVALID",
    CKR_ATTRIBUTE_VALUE_INVALID: "CKR_ATTRIBUTE_VALUE_INVALID",
    CKR_ACTION_PROHIBITED: "CKR_ACTION_PROHIBITED",
    CKR_DATA_INVALID: "CKR_DATA_INVALID",
    CKR_DATA_LEN_RANGE: "CKR_DATA_LEN_RANGE",
    CKR_DEVICE_ERROR: "CKR_DEVICE_ERROR",
    CKR_DEVICE_MEMORY: "CKR_DEVICE_MEMORY",
    CKR_DEVICE_REMOVED: "CKR_DEVICE_REMOVED",
    CKR_ENCRYPTED_DATA_INVALID: "CKR_ENCRYPTED_DATA_INVALID",
    CKR_ENCRYPTED_DATA_LEN_RANGE: "CKR_ENCRYPTED_DATA_LEN_RANGE",
    CKR_FUNCTION_CANCELED: "CKR_FUNCTION_CANCELED",
    CKR_FUNCTION_NOT_PARALLEL: "CKR_FUNCTION_NOT_PARALLEL",
    CKR_FUNCTION_NOT_SUPPORTED: "CKR_FUNCTION_NOT_SUPPORTED",
    CKR_KEY_HANDLE_INVALID: "CKR_KEY_HANDLE_INVALID",
    CKR_KEY_SIZE_RANGE: "CKR_KEY_SIZE_RANGE",
    CKR_KEY_TYPE_INCONSISTENT: "CKR_KEY_TYPE_INCONSISTENT",
    CKR_KEY_NOT_NEEDED: "CKR_KEY_NOT_NEEDED",
    CKR_KEY_CHANGED: "CKR_KEY_CHANGED",
    CKR_KEY_NEEDED: "CKR_KEY_NEEDED",
    CKR_KEY_INDIGESTIBLE: "CKR_KEY_INDIGESTIBLE",
    CKR_KEY_FUNCTION_NOT_PERMITTED: "CKR_KEY_FUNCTION_NOT_PERMITTED",
    CKR_KEY_NOT_WRAPPABLE: "CKR_KEY_NOT_WRAPPABLE",
    CKR_KEY_UNEXTRACTABLE: "CKR_KEY_UNEXTRACTABLE",
    CKR_MECHANISM_INVALID: "CKR_MECHANISM_INVALID",
    CKR_MECHANISM_PARAM_INVALID: "CKR_MECHANISM_PARAM_INVALID",
    CKR_OBJECT_HANDLE_INVALID: "CKR_OBJECT_HANDLE_INVALID",
    CKR_OPERATION_ACTIVE: "CKR_OPERATION_ACTIVE",
    CKR_OPERATION_NOT_INITIALIZED: "CKR_OPERATION_NOT_INITIALIZED",
    CKR_PIN_INCORRECT: "CKR_PIN_INCORRECT",
    CKR_PIN_INVALID: "CKR_PIN_INVALID",
    CKR_PIN_LEN_RANGE: "CKR_PIN_LEN_RANGE",
    CKR_PIN_EXPIRED: "CKR_PIN_EXPIRED",
    CKR_PIN_LOCKED: "CKR_PIN_LOCKED",
    CKR_SESSION_CLOSED: "CKR_SESSION_CLOSED",
    CKR_SESSION_COUNT: "CKR_SESSION_COUNT",
    CKR_SESSION_HANDLE_INVALID: "CKR_SESSION_HANDLE_INVALID",
    CKR_SESSION_PARALLEL_NOT_SUPPORTED: "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
    CKR_SESSION_READ_ONLY: "CKR_SESSION_READ_ONLY",
    CKR_SESSION_EXISTS: "CKR_SESSION_EXISTS",
    CKR_SESSION_READ_ONLY_EXISTS: "CKR_SESSION_READ_ONLY_EXISTS",
    CKR_SESSION_READ_WRITE_SO_EXISTS: "CKR_SESSION_READ_WRITE_SO_EXISTS",
    CKR_SIGNATURE_INVALID: "CKR_SIGNATURE_INVALID",
    CKR_SIGNATURE_LEN_RANGE: "CKR_SIGNATURE_LEN_RANGE",
    CKR_TEMPLATE_INCOMPLETE: "CKR_TEMPLATE_INCOMPLETE",
    CKR_TEMPLATE_INCONSISTENT: "CKR_TEMPLATE_INCONSISTENT",
    CKR_TOKEN_NOT_PRESENT: "CKR_TOKEN_NOT_PRESENT",
    CKR_TOKEN_NOT_RECOGNIZED: "CKR_TOKEN_NOT_RECOGNIZED",
    CKR_TOKEN_WRITE_PROTECTED: "CKR_TOKEN_WRITE_PROTECTED",
    CKR_UNWRAPPING_KEY_HANDLE_INVALID: "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
    CKR_UNWRAPPING_KEY_SIZE_RANGE: "CKR_UNWRAPPING_KEY_SIZE_RANGE",
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
    CKR_USER_ALREADY_LOGGED_IN: "CKR_USER_ALREADY_LOGGED_IN",
    CKR_USER_NOT_LOGGED_IN: "CKR_USER_NOT_LOGGED_IN",
    CKR_USER_PIN_NOT_INITIALIZED: "CKR_USER_PIN_NOT_INITIALIZED",
    CKR_USER_TYPE_INVALID: "CKR_USER_TYPE_INVALID",
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN: "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
    CKR_USER_TOO_MANY_TYPES: "CKR_USER_TOO_MANY_TYPES",
    CKR_WRAPPED_KEY_INVALID: "CKR_WRAPPED_KEY_INVALID",
    CKR_WRAPPED_KEY_LEN_RANGE: "CKR_WRAPPED_KEY_LEN_RANGE",
    CKR_WRAPPING_KEY_HANDLE_INVALID: "CKR_WRAPPING_KEY_HANDLE_INVALID",
    CKR_WRAPPING_KEY_SIZE_RANGE: "CKR_WRAPPING_KEY_SIZE_RANGE",
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT: "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
    CKR_RANDOM_SEED_NOT_SUPPORTED: "CKR_RANDOM_SEED_NOT_SUPPORTED",
    CKR_RANDOM_NO_RNG: "CKR_RANDOM_NO_RNG",
    CKR_DOMAIN_PARAMS_INVALID: "CKR_DOMAIN_PARAMS_INVALID",
    CKR_CURVE_NOT_SUPPORTED: "CKR_CURVE_NOT_SUPPORTED",
    CKR_BUFFER_TOO_SMALL: "CKR_BUFFER_TOO_SMALL",
    CKR_SAVED_STATE_INVALID: "CKR_SAVED_STATE_INVALID",
    CKR_INFORMATION_SENSITIVE: "CKR_INFORMATION_SENSITIVE",
    CKR_STATE_UNSAVEABLE: "CKR_STATE_UNSAVEABLE",
    CKR_CRYPTOKI_NOT_INITIALIZED: "CKR_CRYPTOKI_NOT_INITIALIZED",
    CKR_CRYPTOKI_ALREADY_INITIALIZED: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
    CKR_MUTEX_BAD: "CKR_MUTEX_BAD",
    CKR_MUTEX_NOT_LOCKED: "CKR_MUTEX_NOT_LOCKED",
    CKR_NEW_PIN_MODE: "CKR_NEW_PIN_MODE",
    CKR_NEXT_OTP: "CKR_NEXT_OTP",
    CKR_EXCEEDED_MAX_ITERATIONS: "CKR_EXCEEDED_MAX_ITERATIONS",
    CKR_FIPS_SELF_TEST_FAILED: "CKR_FIPS_SELF_TEST_FAILED",
    CKR_LIBRARY_LOAD_FAILED: "CKR_LIBRARY_LOAD_FAILED",
    CKR_PIN_TOO_WEAK: "CKR_PIN_TOO_WEAK",
    CKR_PUBLIC_KEY_INVALID: "CKR_PUBLIC_KEY_INVALID",
    CKR_FUNCTION_REJECTED: "CKR_FUNCTION_REJECTED"
]
