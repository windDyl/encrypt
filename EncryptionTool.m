//
//  EncryptionTool.m
//  DYPwdDemo
//
//  Created by Ethank on 2017/3/20.
//  Copyright © 2017年 DY. All rights reserved.
//

#import "EncryptionTool.h"

@interface EncryptionTool ()

@property (nonatomic, assign) int keySize;
@property (nonatomic, assign) int blockSize;

@end

@implementation EncryptionTool

+ (instancetype)shareEncrpptionTool {
    static EncryptionTool *singleton = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        singleton = [[self alloc]init];
        singleton.alg = kCCAlgorithmAES;
    });
    return singleton;
}

- (void)setAlg:(uint32_t)alg {
    _alg = alg;
    switch (alg) {
        case kCCAlgorithmDES:
            self.keySize = kCCKeySizeDES;
            self.blockSize = kCCBlockSizeDES;
            break;
          case kCCAlgorithmAES:
            self.keySize = kCCKeySizeAES256;
            self.blockSize = kCCBlockSizeAES128;
        default:
            break;
    }
}

- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {
    //设置密钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cky[self.keySize];
    bzero(cky, sizeof(cky));
    [keyData getBytes:cky length:self.keySize];
    //设置iv
    uint8_t civ[self.blockSize];
    bzero(civ, sizeof(self.blockSize));
    int option = 0;
    if (iv) {
        [iv getBytes:civ length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    //设置输出缓冲区
    NSData *contentData = [string dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [contentData length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    //开始加密
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                         _alg,
                                         option,
                                         cky,
                                         _keySize,
                                         civ,
                                         [contentData bytes],
                                         [contentData length],
                                         buffer,
                                         bufferSize,
                                         &encryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 加密失败|状态编码：%zd", cryptStatus);
    }
    return [result base64EncodedStringWithOptions:0];
}

- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {
    //设置密钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t ckey[self.keySize];
    bzero(ckey, sizeof(ckey));
    [keyData getBytes:ckey length:self.keySize];
    //设置iv
    uint8_t civ[self.blockSize];
    bzero(civ, sizeof(self.blockSize));
    uint8_t option = 0;
    if (iv) {
        [iv getBytes:civ length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    //设置输出缓冲区
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:string options:0];
    size_t bufferSize = [contentData length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    //开始解密
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
            _alg, option,
            ckey,
            _keySize,
            civ,
            [contentData bytes],
            [contentData length],
            buffer,
            bufferSize,
            &encryptedSize);
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytes:buffer length:encryptedSize];
    } else {
        free(buffer);
        NSLog(@"[失败] 解密失败|状态编码：%zd", cryptStatus);
    }
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

@end
