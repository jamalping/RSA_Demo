//
//  Cryptor.h
//  QiyiTvos
//
//  Created by 曹玉姣 on 2018/8/29.
//  Copyright © 2018年 iqiyi. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Cryptor : NSObject
/*AES加密
 *key传16进制String类型
 */
+ (NSData *)AES128EncryptWithKeyStr:(NSString *)key iv:(NSString *)iv data:(NSData *)data;
+ (NSData *)AES128DecryptWithKeyStr:(NSString *)key iv:(NSString *)iv data:(NSData *)data;

/*AES解密
 *key传NSData类型
 */
+ (NSData *)AES128EncryptWithKey:(NSData *)key iv:(NSData *)iv data:(NSData *)data;
+ (NSData *)AES128DecryptWithKey:(NSData *)key iv:(NSData *)iv data:(NSData *)data;


/*RSA加密
 *传data和pubKey
 *return raw data
 */
+ (NSData *)RSAencryptData:(NSData *)data publicKey:(NSString *)pubKey;

/*RSA加密
 *传data和privKey
 *return raw data
 */
+ (NSData *)RSAencryptData:(NSData *)data privateKey:(NSString *)privKey;

/*RSA解密
 *传data和pubKey
 *return raw data
 */
+ (NSData *)RSAdecryptData:(NSData *)data publicKey:(NSString *)pubKey;

/*RSA解密
 *传data和privKey
 *return raw data
 */
+ (NSData *)RSAdecryptData:(NSData *)data privateKey:(NSString *)privKey;

+ (NSString *)loadPubKeyWithPemName:(NSString *)pemName;

/*
 *data转16进制字符串
 */
+ (NSString *)hexEncoding:(NSData*)data;

/*
*16进制转NSData
*/
+ (NSData *)hexDecoding:(NSString *)string;

+ (NSString *)base64_encode_data:(NSData*)data;

+ (NSData *)base64_decode:(NSString *)str;

@end
