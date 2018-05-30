//
//  NSData+CustomPadding.h
//  CommonCrypto
//
//  Created by Harry_L on 2018/5/30.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import <Foundation/Foundation.h>

//[iOS 实现对称加密多种填充方式(ANSIX923、ISO10126、Zero)](https://www.jianshu.com/p/7b6f5aaa7680)
#pragma mark - enum
/*
 Block encryption Mode
 */
typedef enum : NSUInteger {
    CcCryptorNoneMode,
    CcCryptorECBMode = 1,// Electronic Code Book
    CcCryptorCBCMode = 2 // Cipher Block Chaining
}CcCryptorMode;

/*
 Padding Mode
 the length of the sequence of the bytes == (blockSize - (sourceSize's length % blockSize))
 */
typedef enum : NSUInteger {
    CcCryptorNoPadding = 0, //No Padding to source Data
    
    CcCryptorPKCS7Padding = 1, // PKCS_7 | Each byte fills in the length of the sequence of the bytes .  ***This Padding Mode  use the system method.***
    CcCryptorZeroPadding = 2,   // 0x00 Padding |  Each byte fills 0x00
    CcCryptorANSIX923,     // The last byte fills the length of the byte sequence, and the               remaining bytes are filled with 0x00.
    CcCryptorISO10126      // The last byte fills the length of the byte sequence and  the remaining bytes fill the random data.
}CcCryptorPadding;


typedef enum : NSUInteger {
    CcCryptoAlgorithmAES = 0, //Advanced Encryption Standard, 128-bit block.  key 16 24 32 Length
    CcCryptoAlgorithmDES,     //Data Encryption Standard.  Key 8 Length
    CcCryptoAlgorithm3DES,    //Triple-DES, three key 24 Length, EDE configuration
    CcCryptoAlgorithmCAST128,    //CAST, 16Length
    CcCryptoAlgorithmRC4,     //RC4 stream cipher [1,512]Length
    CcCryptoAlgorithmRC2,     // [1,128]Length
    CcCryptoAlgorithmBLOWFISH  // Blowfish block cipher [8,56Length]
}CcCryptoAlgorithm;

@interface NSData (CustomPadding)

#pragma mark - lowCommonCryptor

/**
 
 return An  encrypted NSData.
 
 @param algorithm CcCryptoAlgorithm
 
 @param key The Key Size must be consist With  selected algorithm.
 
 @param iv  The Iv Size must be consist With  selected algorithm.
 
 @param mode CcCryptorMode
 
 @param padding CcCryptorPadding
 
 */
- (NSData *)cc_encryptUsingAlgorithm:(CcCryptoAlgorithm)algorithm
                                 key:(id)key
                InitializationVector:(id)iv
                                Mode:(CcCryptorMode)mode
                             Padding:(CcCryptorPadding)padding;

/**
 
 return An  decrypted NSData.
 
 @param algorithm CcCryptoAlgorithm
 
 @param key The Key Size must be consist With  selected algorithm.
 
 @param iv  The Iv Size must be consist With  selected algorithm.
 
 @param mode CcCryptorMode
 
 @param padding CcCryptorPadding
 
 */
- (NSData *)cc_decryptUsingAlgorithm:(CcCryptoAlgorithm)algorithm
                                 key:(id)key
                InitializationVector:(id)iv
                                Mode:(CcCryptorMode)mode
                             Padding:(CcCryptorPadding)padding;

@end
