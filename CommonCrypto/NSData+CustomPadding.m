//
//  NSData+CustomPadding.m
//  CommonCrypto
//
//  Created by Harry_L on 2018/5/30.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import "NSData+CustomPadding.h"
#import <CommonCrypto/CommonCrypto.h>
@implementation NSData (CustomPadding)

#pragma mark - lowCommonCrypto
- (NSData *)cc_encryptUsingAlgorithm:(CcCryptoAlgorithm)algorithm
                                 key:(id)key
                InitializationVector:(id)iv
                                Mode:(CcCryptorMode)mode
                             Padding:(CcCryptorPadding)padding

{
    
    
    CCCryptorStatus status = kCCSuccess;
    
    
    NSData *result = [self cc_cryptologyUsingOperation:kCCEncrypt
                                             Algorithm:algorithm
                                               Padding:padding
                                                  Mode:mode
                                                   key:key
                                  initializationVector:iv
                                                 error:&status];
    
    
    if ( result != nil )
        return ( result );
    

    return ( nil );
}

- (NSData *)cc_decryptUsingAlgorithm:(CcCryptoAlgorithm)algorithm
                                 key:(id)key
                InitializationVector:(id)iv
                                Mode:(CcCryptorMode)mode
                             Padding:(CcCryptorPadding)padding

{
    
    CCCryptorStatus status = kCCSuccess;
    
    NSData *result = [self cc_cryptologyUsingOperation:kCCDecrypt Algorithm:algorithm Padding:padding Mode:mode key:key initializationVector:iv error:&status];
    
    
    if ( result != nil )
        return ( result );
    
    
    return ( nil );
}


#pragma mark - RootCrypto
- (NSData *)cc_cryptologyUsingOperation:(CCOperation)operation
                              Algorithm: (CCAlgorithm) algorithm
                                Padding:(CcCryptorPadding)padding
                                   Mode:(CcCryptorMode)mode
                                    key: (id) key
                   initializationVector: (id) iv
                                  error: (CCCryptorStatus *) error
{
    // algorithm is not stream chiper
    if (algorithm != kCCAlgorithmRC4 ) {
        NSAssert((mode == CcCryptorCBCMode && iv != nil && iv != NULL) || mode == CcCryptorECBMode, @"With CBC Mode , InitializationVector  must have value");
        NSAssert((mode == CcCryptorCBCMode && [iv length] >= 8) || mode == CcCryptorECBMode, @"With CBC Mode, InitializationVector  must be greater than 8 bits");
        if (mode == CcCryptorCBCMode && [iv length] < 8) {
            NSLog(@"error -- With CBC Mode, InitializationVector  must be greater than 8 bits");
            return nil;
        }
    }
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;
    
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    NSParameterAssert(iv == nil || [iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    
    NSMutableData * keyData, * ivData;
    if ( [key isKindOfClass: [NSData class]] )
        keyData = (NSMutableData *) [key mutableCopy];
    else
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    
    if ( [iv isKindOfClass: [NSString class]] )
        ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    else
        ivData = (NSMutableData *) [iv mutableCopy];    // data or nil
    
#if !__has_feature(objc_arc)
    [keyData autorelease];
    [ivData autorelease];
#endif
    CCPadding paddingMode = ((padding == ccPKCS7Padding) ? ccPKCS7Padding:ccNoPadding) ;
    
    // ensure correct lengths for key and iv data, based on algorithms
    SettingKeyLengths( algorithm, keyData, ivData );
    
    NSData *sourceData =  bitPadding(operation, algorithm, padding, self);
    
    //    status = CCCryptorCreateWithMode(operation, mode, algorithm, ccNoPadding, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_LE, &cryptor);
    status = CCCryptorCreateWithMode(operation, mode, algorithm, paddingMode, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    //  status = CCCryptorCreate( operation, algorithm, kCCOptionPKCS7Padding ,
    //                             [keyData bytes], [keyData length], [ivData bytes],
    //                             &cryptor );
    
    
    if ( status != kCCSuccess )
    {
        if ( error != NULL )
            *error = status;
        return ( nil );
    }
    
    //确定处理给定输入所需的输出缓冲区大小尺寸。
    size_t bufsize = CCCryptorGetOutputLength( cryptor, (size_t)[sourceData length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    
    //处理（加密，解密）一些数据。如果有结果的话,写入提供的缓冲区.
    status = CCCryptorUpdate( cryptor, [sourceData bytes], (size_t)[sourceData length],
                             buf, bufsize, &bufused );
    
    if ( status != kCCSuccess )
    {
        free( buf );
        return ( nil );
    }
    
    bytesTotal += bufused;
    
    // From Brent Royal-Gordon (Twitter: architechies):
    //  Need to update buf ptr past used bytes when calling CCCryptorFinal()
   
    //  It is not necessary to call CCCryptorFinal() when performing
    //symmetric encryption or decryption if padding is disabled, or
    //   when using a stream cipher.
    if (mode == CcCryptorPKCS7Padding) {
        status = CCCryptorFinal( cryptor, buf + bufused, bufsize - bufused, &bufused );
        if ( status != kCCSuccess )
        {
            free( buf );
            return ( nil );
        }
        bytesTotal += bufused;
    }
    
    NSData *result = [NSData dataWithBytesNoCopy: buf length: bytesTotal];
    
    result = removeBitPadding(operation, algorithm, padding, result);
    
    if ( (result == nil) && (error != NULL) )
        *error = status;
    
    CCCryptorRelease( cryptor );
    
    return ( result );
}


// Check the length of key and IV , fix them.
static void SettingKeyLengths( CCAlgorithm algorithm, NSMutableData * keyData, NSMutableData * ivData)
{
    NSUInteger keyLength = [keyData length];
    switch ( algorithm )
    {
        case kCCAlgorithmAES128:
        {
            // 16
            if ( keyLength <= kCCKeySizeAES128 )
            {
                [keyData setLength: kCCKeySizeAES128];
            }
            // 24
            else if ( keyLength <= kCCKeySizeAES192 )
            {
                [keyData setLength: kCCKeySizeAES192];
            }
            // 32
            else
            {
                [keyData setLength: kCCKeySizeAES256];
            }
            
            break;
        }
            
        case kCCAlgorithmDES:
        {
            // 8
            [keyData setLength: kCCKeySizeDES];
            break;
        }
            
        case kCCAlgorithm3DES:
        {
            //24
            [keyData setLength: kCCKeySize3DES];
            break;
        }
            
        case kCCAlgorithmCAST:
        {
            //[5,16]
            //            if ( keyLength < kCCKeySizeMinCAST )
            //            {
            //                [keyData setLength: kCCKeySizeMinCAST];
            //            }
            //            else if ( keyLength > kCCKeySizeMaxCAST )
            //            {
            // 16
            [keyData setLength: kCCKeySizeMaxCAST];
            //            }
            
            break;
        }
            
        case kCCAlgorithmRC4:
        {
            // [1,512]
            if ( keyLength >= kCCKeySizeMaxRC4 )
                [keyData setLength: kCCKeySizeMaxRC4 ];
            break;
        }
        case kCCAlgorithmRC2:
        {
            // [1,128]
            if ( keyLength >= kCCKeySizeMaxRC2 )
                [keyData setLength: kCCKeySizeMaxRC2 ];
            break;
        }
        default:
            break;
    }
    
    
    [ivData setLength: [keyData length]];
}

// Fill in the bytes that need to be encrypted.
static NSData * bitPadding(CCOperation operation, CCAlgorithm algorithm ,CcCryptorPadding padding, NSData *data)
{
    
    if (padding == CcCryptorPKCS7Padding) {
        return  data;
    }
    if (operation == kCCEncrypt && (algorithm != CcCryptoAlgorithmRC4)  ) {
        NSMutableData *sourceData = data.mutableCopy;
        int blockSize = 8;
        switch (algorithm) {
            case kCCAlgorithmAES:
                blockSize = kCCBlockSizeAES128;
                break;
            case kCCAlgorithmDES:
            case kCCAlgorithm3DES:
            case kCCAlgorithmCAST:
            case kCCAlgorithmBlowfish:
            default:
                blockSize = 8;
                break;
        }
        
        switch (padding) {
            case CcCryptorZeroPadding:
            {
                int pad = 0x00;
                int diff =   blockSize - (sourceData.length % blockSize);
                for (int i = 0; i < diff; i++) {
                    [sourceData appendBytes:&pad length:1];
                }
            }
                break;
            case CcCryptorANSIX923:
            {
                int pad = 0x00;
                int diff =   blockSize - (sourceData.length % blockSize);
                for (int i = 0; i < diff - 1; i++) {
                    [sourceData appendBytes:&pad length:1];
                }
                [sourceData appendBytes:&diff length:1];
            }
                break;
            case CcCryptorISO10126:
            {
                int diff = blockSize - (sourceData.length % blockSize);
                for (int i = 0; i < diff - 1; i++) {
                    int pad  = arc4random() % 254 + 1;
                    [sourceData appendBytes:&pad length:1];
                }
                [sourceData appendBytes:&diff length:1];
            }
                break;
                //            case CcCryptorPKCS7Padding:
                //            {
                //                int diff =  blockSize - ([sourceData length] % blockSize);
                //                for (int i = 0; i <diff; i++) {
                //                    [sourceData appendBytes:&diff length:1];
                //                }
                //
                //            }
            default:
                break;
        }
        return sourceData;
    }
    return data;
    
}

//Remove the filled character  for the decrypted data.
static NSData * removeBitPadding(CCOperation operation, CCAlgorithm algorithm ,CcCryptorPadding padding, NSData *sourceData)
{
    if (padding == CcCryptorPKCS7Padding) {
        return sourceData;
    }
    if (operation == kCCDecrypt && (algorithm != CcCryptoAlgorithmRC4) ) {
        
        int correctLength = 0;
        int blockSize = 8;
        switch (algorithm) {
            case kCCAlgorithmAES:
                blockSize = kCCBlockSizeAES128;
                break;
            case kCCAlgorithmDES:
            case kCCAlgorithm3DES:
            case kCCAlgorithmCAST:
            case kCCAlgorithmBlowfish:
            default:
                blockSize = 8;
                break;
        }
        Byte *testByte = (Byte *)[sourceData bytes];
        char end = testByte[sourceData.length - 1];
        // 去除可能填充字符
        //        if ((padding == CcCryptorZeroPadding && end == 0) || (padding == ccPKCS7Padding && (end > 0 && end < blockSize + 1))) {
        if (padding == CcCryptorZeroPadding && end == 0) {
            for (int i = (short)sourceData.length - 1; i > 0 ; i--) {
                if (testByte[i] != end) {
                    correctLength = i + 1;
                    break;
                }
            }
        }
        else if ((padding == CcCryptorANSIX923 || padding == CcCryptorISO10126) && (end > 0 && end < blockSize + 1)){
            if (padding == CcCryptorISO10126 || ( testByte[sourceData.length - 2] == 0 &&  testByte[sourceData.length - end] == 0)) {
                correctLength = (short)sourceData.length - end;
            }
        }
        
        NSData *data = [NSData dataWithBytes:testByte length:correctLength];
        return data;
        
    }
    return sourceData;
    
}


@end
