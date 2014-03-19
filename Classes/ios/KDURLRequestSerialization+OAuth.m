//
//  KDURLRequestSerialization.m
//  Weibo
//
//  Created by 王 松 on 14-3-18.
//  Copyright (c) 2014年 Song.wang. All rights reserved.
//

#import "KDURLRequestSerialization+OAuth.h"
#import "NSMutableURLRequest+OAuth.h"
#import "KDCommon.h"

@implementation KDHTTPRequestSerializer

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method
                                 URLString:(NSString *)URLString
                                parameters:(id)parameters
                                     error:(NSError * __autoreleasing *)error
{
    NSMutableURLRequest *request = [super requestWithMethod:method URLString:URLString parameters:parameters error:error];
    [self setOAuthorizationHeader:request];
    return request;
}

- (NSMutableURLRequest *)multipartFormRequestWithMethod:(NSString *)method
                                              URLString:(NSString *)URLString
                                             parameters:(NSDictionary *)parameters
                              constructingBodyWithBlock:(void (^)(id <AFMultipartFormData> formData))block
                                                  error:(NSError * __autoreleasing *)error
{
    NSMutableURLRequest *request = [super multipartFormRequestWithMethod:method URLString:URLString parameters:parameters constructingBodyWithBlock:block error:error];
    [self setOAuthorizationHeader:request];
    return request;
}

- (NSMutableURLRequest *)requestWithMultipartFormRequest:(NSURLRequest *)request
                             writingStreamContentsToFile:(NSURL *)fileURL
                                       completionHandler:(void (^)(NSError *error))handler
{
    NSMutableURLRequest *mRequest = [super requestWithMultipartFormRequest:request writingStreamContentsToFile:fileURL completionHandler:handler];
    [self setOAuthorizationHeader:mRequest];
    return mRequest;
}

- (void)setOAuthorizationHeader:(NSMutableURLRequest *)request
{
    if ([self isUseOAuth]) {
        [request signRequestWithClientIdentifier:KD_DEFAULT_OAUTH_CONSUMER_KEY secret:KD_DEFAULT_OAUTH_CONSUMER_SECRET tokenIdentifier:self.oAuthToken secret:self.oAuthTokenSecret usingMethod:OAuthHMAC_SHA1SignatureMethod];
    }else {
        [self clearAuthorizationHeader];
    }
}
@end
