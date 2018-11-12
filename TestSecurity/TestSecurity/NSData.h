//
//  NSData.h
//  security
//
//  Created by Xin Li on 2018/8/27.
//  Copyright © 2018 Xin Li. All rights reserved.
//

#ifndef NSData_h
#define NSData_h

#import <Foundation/Foundation.h>

@class NSString;

@interface NSData (Encryption)

- (NSData *)AES128EncryptWithKey:(NSString *)key;
- (NSData *)AES128DecryptWithKey:(NSString *)key;
- (NSString *)HexEncoding;

@end

#endif /* NSData_h */
