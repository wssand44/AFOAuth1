//
//  KDURLRequestSerialization.h
//  Weibo
//
//  Created by 王 松 on 14-3-18.
//  Copyright (c) 2014年 Song.wang. All rights reserved.
//

#import "AFURLRequestSerialization.h"

@interface KDHTTPRequestSerializer : AFHTTPRequestSerializer

@property(assign, nonatomic, getter = isUseOAuth) BOOL useOAuth;

@property(strong, nonatomic) NSString *oAuthToken;

@property(strong, nonatomic) NSString *oAuthTokenSecret;

@end


