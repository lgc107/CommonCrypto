//
//  NSData+CommomCrypto.m
//  CommonCrypto
//
//  Created by Harry_L on 2018/5/27.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import "NSData+CommomCryptor.h"

@implementation NSData (CommomCryptor)

-(NSData *)encryptWithAlgorithm:(CCAlgorithm)algorithm options:(CCOptions)option Key:(NSString *)key Iv:(NSString *)iv{
    //一.Create
//    CCOperation operation = kCCEncrypt; //kCCEncrypt | KCCDecrypt  加密 | 解密
//    CCAlgorithm algorithm = kCCAlgorithmAES; // 算法以AES为例
//    CCOptions options = kCCOptionPKCS7Padding; // 填补方式以 kCCOptionPKCS7Padding 为例.若使用ECB模式，则为kCCOptionPKCS7Padding | kCCOptionECBMode.
    // 生成一个长度16的密匙数据
    NSMutableData *keyData =  [key dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    // 生成一个长度16的向量数据,若不生成可传NULL，苹果文档有这样一段话 If CBC mode is selected and no IV is provided, an IV of all zeroes will be used.指出在CBC模式下，如果没有提供IV向量，则默认使用字节全为0x00的一个IV向量。
    NSMutableData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    // 声明 CCCryptoRef 用于返回结果数据.
    CCCryptorRef cryptorRef;
    //我们要对密匙长度做一个判断
    SettingKeyLengths(algorithm, keyData, ivData);
    // 1.create创建第一种函数.
    // CCCryptorCreate()函数通过指定加解密、算法、默认CBC模式、密匙长度和密匙字节及向量字节返回一个CCCryptorRef的对象
   CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, algorithm, option, keyData.bytes, keyData.length, ivData.bytes, &cryptorRef);
    if ( status != kCCSuccess )
    {
        NSLog(@"失败原因%d",status);
        return nil;
    }
    
    //确定处理给定输入所需的输出缓冲区大小尺寸。
    size_t bufsize = CCCryptorGetOutputLength( cryptorRef, (size_t)[self length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    //调用Update函数,处理（加密，解密）一些数据。如果有结果的话,写入提供的缓冲区.
    status = CCCryptorUpdate( cryptorRef, [self bytes], (size_t)[self length],
                             buf, bufsize, &bufused );
    if ( status != kCCSuccess )
    {
        free( buf );
        NSLog(@"失败原因%d",status);
        return nil;
    }
    bytesTotal += bufused;
    
    // From Brent Royal-Gordon (Twitter: architechies):
    //  Need to update buf ptr past used bytes when calling CCCryptorFinal()
    status = CCCryptorFinal( cryptorRef, buf + bufused, bufsize - bufused, &bufused );
    if ( status != kCCSuccess )
    {
        free( buf );
        NSLog(@"失败原因%d",status);
        return nil;
    }
    
    bytesTotal += bufused;
    
    NSData *result = [NSData dataWithBytesNoCopy:buf length: bytesTotal];
    
     CCCryptorRelease( cryptorRef);
    
    return result;
//
}

-(NSData *)decryptWithAlgorithm:(CCAlgorithm)algorithm options:(CCOptions)option Key:(NSString *)key Iv:(NSString *)iv{
    //一.Create
    //    CCOperation operation = kCCEncrypt; //kCCEncrypt | KCCDecrypt  加密 | 解密
    //    CCAlgorithm algorithm = kCCAlgorithmAES; // 算法以AES为例
    //    CCOptions options = kCCOptionPKCS7Padding; // 填补方式以 kCCOptionPKCS7Padding 为例.若使用ECB模式，则为kCCOptionPKCS7Padding | kCCOptionECBMode.
    // 生成一个长度16的密匙数据
    NSMutableData *keyData =  [key dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    // 生成一个长度16的向量数据,若不生成可传NULL，苹果文档有这样一段话 If CBC mode is selected and no IV is provided, an IV of all zeroes will be used.指出在CBC模式下，如果没有提供IV向量，则默认使用字节全为0x00的一个IV向量。
    NSMutableData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding].mutableCopy;
    // 声明 CCCryptoRef 用于返回结果数据.
    CCCryptorRef cryptorRef;
    //我们要对密匙长度做一个判断
    SettingKeyLengths(algorithm, keyData, ivData);
    // 1.create创建第一种函数.
    // CCCryptorCreate()函数通过指定加解密、算法、默认CBC模式、密匙长度和密匙字节及向量字节返回一个CCCryptorRef的对象
    CCCryptorStatus status = CCCryptorCreate(kCCDecrypt, algorithm, option, keyData.bytes, keyData.length, ivData.bytes, &cryptorRef);
    if ( status != kCCSuccess )
    {
        NSLog(@"失败原因%d",status);
        return nil;
    }
    
    //确定处理给定输入所需的输出缓冲区大小尺寸。
    size_t bufsize = CCCryptorGetOutputLength( cryptorRef, (size_t)[self length], true );
    void * buf = malloc( bufsize );
    size_t bufused = 0;
    size_t bytesTotal = 0;
    //调用Update函数,处理（加密，解密）一些数据。如果有结果的话,写入提供的缓冲区.
    status = CCCryptorUpdate( cryptorRef, [self bytes], (size_t)[self length],
                             buf, bufsize, &bufused );
    if ( status != kCCSuccess )
    {
        free( buf );
        NSLog(@"失败原因%d",status);
        return nil;
    }
    bytesTotal += bufused;
    
    // From Brent Royal-Gordon (Twitter: architechies):
    //  Need to update buf ptr past used bytes when calling CCCryptorFinal()
    status = CCCryptorFinal( cryptorRef, buf + bufused, bufsize - bufused, &bufused );
    if ( status != kCCSuccess )
    {
        free( buf );
        NSLog(@"失败原因%d",status);
        return nil;
    }
    
    bytesTotal += bufused;
    
    NSData *result = [NSData dataWithBytesNoCopy:buf length: bytesTotal];
    
    CCCryptorRelease( cryptorRef);
    
    return result;
    //
}

-(void)cryptoSecondMethod{
    //一.Create
    CCOperation operation = kCCEncrypt; //kCCEncrypt | KCCDecrypt  加密 | 解密
    CCAlgorithm algorithm = kCCAlgorithmAES; // 算法以AES为例.
    // 生成一个长度16的密匙数据
    NSData *keyData =  [@"16TestEncryptKey" dataUsingEncoding:NSUTF8StringEncoding];
    // 生成一个长度16的向量数据,若不生成可传NULL，苹果文档有这样一段话 If CBC mode is selected and no IV is provided, an IV of all zeroes will be used.指出在CBC模式下，如果没有提供IV向量，则默认使用字节全为0x00的一个IV向量。
    NSData *ivData = [@"16TestEncryptIv" dataUsingEncoding:NSUTF8StringEncoding];
    // 声明 CCCryptoRef 用于返回结果数据.
    if (algorithm == kCCAlgorithmAES) {
        // 若密匙长度大于16小于24，则判断值应为kCCKeySizeAES192.
        if (keyData.length < kCCKeySizeAES128) {
            //两种处理办法
            //1.补足位数.
            NSMutableData *handleData = keyData.mutableCopy;
            
            [handleData setLength:kCCKeySizeAES128];
            
            keyData = handleData;
            //2.返回加密失败.
            NSLog(@"密匙长度不足16位");
            return;
        }
    }
    CCCryptorRef cryptorRef;
    CCMode mode = kCCModeCBC; // 可选加密模式 CBC、EBC,官方提供的文档还可以选择CFB、CTR、  OFB、XTS等.
    CCPadding padding = ccPKCS7Padding; //填补模式  ccPKCS7Padding、ccNoPadding.
    // 2.create创建第二种函数
    //CCCryptorCreateWithMode()函数通过指定加解密、模式、算法、填充模式、密匙长度和密匙字节及向量字节返回一个CCCryptorRef的对象.tweak key以及tweak key length默认可以设置为0，在XTS模式下才会用到
    CCCryptorStatus status = CCCryptorCreateWithMode(operation, mode, algorithm, padding, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, 0, &cryptorRef);
    if ( status != kCCSuccess )
    {
        NSLog(@"失败原因%d",status);
    }
    
    
}

- (NSData *)encryptWithAlgorithm:(CCAlgorithm)algorithm Key:(NSData *)key iv:(NSData *)iv {
  
    NSMutableData *keyData = key.mutableCopy;
    NSMutableData *ivData = iv.mutableCopy;
    SettingKeyLengths(algorithm, keyData, ivData);
    CCOptions options = kCCOptionECBMode | kCCOptionPKCS7Padding;
    //options = kCCOptionPKCS7Padding;
    
    int blockSize =  (algorithm == kCCAlgorithmAES) ? 16 : 8 ;
    
    NSData *result = nil;
    size_t bufferSize = self.length + blockSize;
    void *buffer = malloc(bufferSize);
    if (!buffer) return nil;
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          algorithm,
                                          options,
                                          keyData.bytes,
                                          keyData.length,
                                          ivData.bytes,
                                          self.bytes,
                                          self.length,
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [[NSData alloc]initWithBytes:buffer length:encryptedSize];
        free(buffer);
        return result;
    } else {
        free(buffer);
        return nil;
    }
}

- (NSData *)decryptWithAlgorithm:(CCAlgorithm)algorithm Key:(NSData *)key iv:(NSData *)iv {
    
   
    NSMutableData *keyData = key.mutableCopy;
    NSMutableData *ivData = iv.mutableCopy;
    SettingKeyLengths(algorithm, keyData, ivData);
    CCOptions options = kCCOptionECBMode | kCCOptionPKCS7Padding;
    //options = kCCOptionPKCS7Padding;
    
    int blockSize =  (algorithm == kCCAlgorithmAES) ? 16 : 8 ;
    
    NSData *result = nil;
    size_t bufferSize = self.length + blockSize;
    void *buffer = malloc(bufferSize);
    if (!buffer) return nil;
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          algorithm,
                                          options,
                                          keyData.bytes,
                                          keyData.length,
                                          ivData.bytes,
                                          self.bytes,
                                          self.length,
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        result = [[NSData alloc]initWithBytes:buffer length:encryptedSize];
        free(buffer);
        return result;
    } else {
        free(buffer);
        return nil;
    }
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


@end
