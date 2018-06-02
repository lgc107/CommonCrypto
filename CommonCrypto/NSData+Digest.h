//
//  NSDate+Digest.h
//  CommonCrypto
//
//  Created by Harry_L on 2018/6/2.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Digest)

#pragma mark - ReturnData  (Digest)

/**
 Returns an NSData for md2 hash.
 */
- (NSData *)cc_md2Data;
/**
 Returns an NSData for md4 hash.
 */
- (NSData *)cc_md4Data;
/**
 Returns an NSData for md5 hash.
 */
- (NSData *)cc_md5Data;
/**
 Returns an NSData for sha1 hash.
 */
- (NSData *)cc_sha1Data;
/**
 Returns an NSData for sha224 hash.
 */
- (NSData *)cc_sha224Data;
/**
 Returns an NSData for 256 hash.
 */
- (NSData *)cc_sha256Data;
/**
 Returns an NSData for 384 hash.
 */
- (NSData *)cc_sha384Data;
/**
 Returns an NSData for 512 hash.
 */
- (NSData *)cc_sha512Data;

#pragma mark - ReturnString  (Digest)

/**
 Returns a lowercase NSString for md2 hash.
 */
- (NSString *)cc_md2String;
/**
 Returns a lowercase NSString for md4 hash.
 */
- (NSString *)cc_md4String;
/**
 Returns a lowercase NSString for md5 hash.
 */
- (NSString *)cc_md5String;
/**
 Returns a lowercase NSString for sha1 hash.
 */
- (NSString *)cc_sha1String;
/**
 Returns a lowercase NSString for sha224 hash.
 */
- (NSString *)cc_sha224String;
/**
 Returns a lowercase NSString for sha256 hash.
 */
- (NSString *)cc_sha256String;
/**
 Returns a lowercase NSString for sha384 hash.
 */
- (NSString *)cc_sha384String;
/**
 Returns a lowercase NSString for sha512 hash.
 */
- (NSString *)cc_sha512String;
@end
