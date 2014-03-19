//
//  NSString+URLEncode.h
//  Weibo
//
//  Created by 王 松 on 14-3-18.
//  Copyright (c) 2014年 Song.wang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (URLEncode)

- (NSString *)encodeForURL;
- (NSString *)encodeForURLReplacingSpacesWithPlus;
- (NSString *)decodeFromURL;

@end
