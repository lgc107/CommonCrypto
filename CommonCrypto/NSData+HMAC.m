//
//  NSData+HMAC.m
//  CommonCrypto
//
//  Created by Harry_L on 2018/6/2.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import "NSData+HMAC.h"
#import <CommonCrypto/CommonHMAC.h>
@implementation NSData (HMAC)
#pragma mark - returnData  (Hash-based Message Authentication Code)

- (NSData *)cc_hmacMD5DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgMD5 withKey:key];
}

- (NSData *)cc_hmacSHA1DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgSHA1 withKey:key];
}

- (NSData *)cc_hmacSHA224DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgSHA224 withKey:key];
}

- (NSData *)cc_hmacSHA256DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgSHA256 withKey:key];
}

- (NSData *)cc_hmacSHA384DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgSHA384 withKey:key];
}

- (NSData *)cc_hmacSHA512DataWithKey:(id)key{
    return [self cc_hmacDataUsingAlg:kCCHmacAlgSHA512 withKey:key];
}


#pragma mark - returnString  (Hash-based Message Authentication Code)
- (NSString *)cc_hmacMD5StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgMD5 withKey:key];
}

- (NSString *)cc_hmacSHA1StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA1 withKey:key];
}

- (NSString *)cc_hmacSHA224StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA224 withKey:key];
}

- (NSString *)cc_hmacSHA256StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA256 withKey:key];
}


- (NSString *)cc_hmacSHA384StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA384 withKey:key];
}

- (NSString *)cc_hmacSHA512StringWith:(id)key{
    return [self cc_hmacStringUsingAlg:kCCHmacAlgSHA512 withKey:key];
}

#pragma mark - hmac_root
- (NSData *)cc_hmacDataUsingAlg:(CCHmacAlgorithm)alg withKey:(id)key {
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    size_t size;
    switch (alg) {
        case kCCHmacAlgMD5: size = CC_MD5_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA1: size = CC_SHA1_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA224: size = CC_SHA224_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA256: size = CC_SHA256_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA384: size = CC_SHA384_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA512: size = CC_SHA512_DIGEST_LENGTH; break;
        default: return nil;
    }
    NSMutableData * keyData;
    if ( [key isKindOfClass: [NSData class]] )
        keyData = (NSMutableData *) [key mutableCopy];
    else
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    
    unsigned char result[size];
    CCHmac(alg, [keyData bytes], keyData.length, self.bytes, self.length, result);
    return [NSData dataWithBytes:result length:size];
}

- (NSString *)cc_hmacStringUsingAlg:(CCHmacAlgorithm)alg withKey:(id)key {
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    size_t size;
    switch (alg) {
        case kCCHmacAlgMD5: size = CC_MD5_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA1: size = CC_SHA1_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA224: size = CC_SHA224_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA256: size = CC_SHA256_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA384: size = CC_SHA384_DIGEST_LENGTH; break;
        case kCCHmacAlgSHA512: size = CC_SHA512_DIGEST_LENGTH; break;
        default: return nil;
    }
    unsigned char result[size];
    NSMutableData * keyData;
    if ( [key isKindOfClass: [NSData class]] )
        keyData = (NSMutableData *) [key mutableCopy];
    else
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    
    CCHmac(alg, keyData.bytes, strlen(keyData.bytes), self.bytes, self.length, result);
    NSMutableString *hash = [NSMutableString stringWithCapacity:size * 2];
    for (int i = 0; i < size; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    return hash;
}

@end
