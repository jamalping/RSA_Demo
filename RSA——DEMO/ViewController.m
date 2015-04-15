//
//  ViewController.m
//  RSA——DEMO
//
//  Created by jamalping on 15-4-7.
//  Copyright (c) 2015年 李小平. All rights reserved.
//

#import "ViewController.h"
#import "RSAEncryptor.h"

///RSA 加密代码、之前还需生成必要的公钥，私钥、证书，详情参考：http://www.cnblogs.com/makemelike/articles/3802518.html

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *m= @"Your HEX modulus here";
    
    RSAEncryptor *rsaEncryptor = [[RSAEncryptor alloc] init];
    NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"];
//    NSString *privateKeyPath = [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"];
    
    [rsaEncryptor loadPublicKeyFromFile: publicKeyPath];
//    [rsaEncryptor loadPrivateKeyFromFile: privateKeyPath password:@"cjis"];
    
    NSString* restrinBASE64STRING = [rsaEncryptor rsaEncryptString:m];
    NSLog(@"Encrypted: %@", restrinBASE64STRING);
//    NSString* decryptString = [rsaEncryptor rsaDecryptString: restrinBASE64STRING];
//    NSLog(@"Decrypted: %@", decryptString);
    
//    NSString *rsaStr = [rsaEncryptor rsaEncryptString:m];
//    NSLog(@"%@",rsaStr);
//    NSString *e=@"Your HEX exponent";
//    NSString * hexString= @"Your HEX message here";
//    
//    NSData *decryptedIPKC= [self decryptIPKC:hexString modulus:m exponent:e];
//    NSLog(@"ESTE ES EL NSDATA %@", decryptedIPKC.description);
    
}

@end
