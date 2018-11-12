//
//  ViewController.m
//  TestSecurity
//
//  Created by 曹玉姣 on 2018/11/12.
//  Copyright © 2018年 曹玉姣. All rights reserved.
//

#import "ViewController.h"
#import "Cryptor.h"
#import "NSData.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSData *data = [@"abcdefg" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [data AES128EncryptWithKey:@"abcdefghijklmnop"];
    NSLog(@"encrypted: %@",[encryptedData HexEncoding]);
    
    
    NSString *secrect = @"510710520feb6d3a91a77bdb3ce58b880b3237e9821a67118ab57baef7f6d826b0f80f00b5ea1d1fe333e8f0ee52b1065f323d4609d1b4eb3037fc17d88409e267473c9e5fa05bf7ad130fc2a00c5d0a63c703ed06b24bdc9cc3e60e10c084fcecd4ccef54284ba98374ae6a9c0f70534080b5dd7b6f0df449ce270a7bb48300";
    NSData *hexDecodeSecret = [Cryptor hexDecoding:secrect];
    
    NSString *publicKey = [Cryptor loadPubKeyWithPemName:@"public"];
    
    NSData * realSecrect = [Cryptor RSAdecryptData:hexDecodeSecret publicKey:publicKey];
    
    NSString *a1 = [Cryptor base64_encode_data:realSecrect];
    NSString *key = [Cryptor hexEncoding:realSecrect];
    NSLog(@"a1a1a1a1:%@",a1);
}


@end
