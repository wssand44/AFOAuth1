//
//  NSURLRequest+OAuth.h
//  Weibo
//
//  Created by 王 松 on 14-3-18.
//  Copyright (c) 2014年 Song.wang. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum OAuthSignatureMethod {
    OAuthPlaintextSignatureMethod,
    OAuthHMAC_SHA1SignatureMethod,
} OAuthSignatureMethod;

@interface NSMutableURLRequest (OAuth)

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                            usingMethod:(OAuthSignatureMethod)signatureMethod;

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                               verifier:(NSString *)verifier
                            usingMethod:(OAuthSignatureMethod)signatureMethod;

- (NSString *)oauthTokenWithClientIdentifier:(NSString *)clientIdentifier
                                      secret:(NSString *)clientSecret
                             tokenIdentifier:(NSString *)tokenIdentifier
                                      secret:(NSString *)tokenSecret
                                    verifier:(NSString *)verifier
                                 usingMethod:(OAuthSignatureMethod)signatureMethod;

@end

