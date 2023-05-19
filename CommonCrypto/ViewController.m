//
//  ViewController.m
//  CommonCrypto
//
//  Created by Harry_L on 2018/5/27.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import "ViewController.h"
#import "NSData+CommomCryptor.h"
#import "NSData+CustomPadding.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    //for example
    
    NSString *key = @"1234567890123456";
    NSString *iv = @"1234567890123456";
    NSString *source = @"12345";
    
    //String -> Data
    NSData *sourceData = [source dataUsingEncoding:NSUTF8StringEncoding];
    // Data -> AESEncrypt
    NSData *ansix923Data = [sourceData cc_encryptUsingAlgorithm:CcCryptoAlgorithmAES key:key InitializationVector:iv Mode:CcCryptorCBCMode Padding:CcCryptorANSIX923];
    NSString *ansix923String = [ansix923Data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"%@",ansix923String);
    
    // Data -> AESDecrypt
    NSData *decryptAnsix923Data = [ansix923Data cc_decryptUsingAlgorithm:CcCryptoAlgorithmAES key:key InitializationVector:iv Mode:CcCryptorCBCMode Padding:CcCryptorANSIX923];
    NSString *decryptString = [[NSString alloc] initWithData:decryptAnsix923Data  encoding:NSUTF8StringEncoding];
    NSLog(@"%@",decryptString);
    
    
    NSString *res1 =  [sourceData cc_hmacMD5StringWith:key];
    NSString *res2 = [[NSString alloc] initWithData:[sourceData cc_hmacMD5DataWithKey:key] encoding:NSUTF8StringEncoding];
    
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
