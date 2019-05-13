//
//  Bridging.h
//  authndemo
//
//  Created by Ales Teska on 11.5.19.
//  Copyright © 2019 TeskaLabs. All rights reserved.
//

#ifndef Bridging_h
#define Bridging_h

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif /* Bridging_h */
