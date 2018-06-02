//
//  NSData+CommomCrypto.h
//  CommonCrypto
//
//  Created by Harry_L on 2018/5/27.
//  Copyright © 2018年 Harry_L. All rights reserved.
//

// 简单的加密实现.若有问题可以私信我 相关简书网址为：https://www.jianshu.com/p/8896ed432dff.

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>


@interface NSData (CommomCryptor)

-(NSData *)encryptWithAlgorithm:(CCAlgorithm)algorithm options:(CCOptions)option Key:(NSString *)key Iv:(NSString *)iv;
-(NSData *)decryptWithAlgorithm:(CCAlgorithm)algorithm options:(CCOptions)option Key:(NSString *)key Iv:(NSString *)iv;
- (NSData *)encryptWithAlgorithm:(CCAlgorithm)algorithm Key:(NSData *)key iv:(NSData *)iv;
- (NSData *)decryptWithAlgorithm:(CCAlgorithm)algorithm Key:(NSData *)key iv:(NSData *)iv;
@end
