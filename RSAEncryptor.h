//
//  RSAEncryptor.h
//  RSA——DEMO
//
//  Created by jamalping on 15-4-8.
//  Copyright (c) 2015年 李小平. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAEncryptor : NSObject

#pragma mark - Instance Methods
/**
 * @brief  获取公钥从文件中获取
 *
 * @param derFilePath 存放公钥的文件的路径
 */
-(void) loadPublicKeyFromFile: (NSString*) derFilePath;

/**
 * @brief  获取私钥
 *
 * @param p12FilePath 存放私钥的文件的路径
 * @param p12Password 密码（创建证书时设置的密码）
 */
-(void) loadPrivateKeyFromFile: (NSString*) p12FilePath password:(NSString*)p12Password;

/**
 * @brief  rsa加密
 *
 * @param string 被加密的字符串
 *
 * @return 加密后的字符串
 */
-(NSString*) rsaEncryptString:(NSString*)string;

/**
 * @brief  rsa解密
 *
 * @param string 被解密的字符串
 *
 * @return 解密后的字符串
 */
-(NSString*) rsaDecryptString:(NSString*)string;

#pragma mark - Class Methods

/**
 * @brief  加密解密对象单例
 *
 * @return 单例
 */

+(RSAEncryptor*) sharedInstance;

@end
