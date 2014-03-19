//
//  NSURLRequest+OAuth.m
//  Weibo
//
//  Created by 王 松 on 14-3-18.
//  Copyright (c) 2014年 Song.wang. All rights reserved.
//

#import "NSMutableURLRequest+OAuth.h"
#include <sys/time.h>

#import <CommonCrypto/CommonHMAC.h>
#import "NSString+URLEncode.h"


@implementation NSMutableURLRequest (OAuth)

// Signature Method strings, keep in sync with OAuthSignatureMethod
static const NSString *oauthSignatureMethodName[] = {
    @"PLAINTEXT",
    @"HMAC-SHA1",
};

// OAuth version implemented here
static const NSString *oauthVersion = @"1.0";

#pragma mark -
#pragma mark Timestamp and nonce handling

- (NSArray *)oauthGenerateTimestampAndNonce
{
    static time_t last_timestamp = -1;
    static NSMutableSet *nonceHistory = nil;
    
    // Make sure we never send the same timestamp and nonce
    if (!nonceHistory)
        nonceHistory = [[NSMutableSet alloc] init];
    
    struct timeval tv;
    NSString *timestamp, *nonce;
    do {
        // Get the time of day, for both the timestamp and the random seed
        gettimeofday(&tv, NULL);
        
        // Generate a random alphanumeric character sequence for the nonce
        char nonceBytes[16];
        srandom((int)tv.tv_sec | (int)tv.tv_usec);
        for (int i = 0; i < 16; i++) {
            int byte = random() % 62;
            if (byte < 26)
                nonceBytes[i] = 'a' + byte;
            else if (byte < 52)
                nonceBytes[i] = 'A' + byte - 26;
            else
                nonceBytes[i] = '0' + byte - 52;
        }
        
        timestamp = [NSString stringWithFormat:@"%d", (int)tv.tv_sec];
        nonce = [NSString stringWithFormat:@"%.16s", nonceBytes];
    } while ((tv.tv_sec == last_timestamp) && [nonceHistory containsObject:nonce]);
    
    if (tv.tv_sec != last_timestamp) {
        last_timestamp = tv.tv_sec;
        [nonceHistory removeAllObjects];
    }
    [nonceHistory addObject:nonce];
    
    return [NSArray arrayWithObjects:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_timestamp", @"key", timestamp, @"value", nil], [NSDictionary dictionaryWithObjectsAndKeys:@"oauth_nonce", @"key", nonce, @"value", nil], nil];
}


#pragma mark -
#pragma mark Signature base string construction

- (NSString *)oauthBaseStringURI
{
    // Port need only be present if it's not the default
    NSString *hostString;
    if (([self.URL port] == nil)
        || ([[[self.URL scheme] lowercaseString] isEqualToString:@"http"] && ([[self.URL port] integerValue] == 80))
        || ([[[self.URL scheme] lowercaseString] isEqualToString:@"https"] && ([[self.URL port] integerValue] == 443))) {
        hostString = [[self.URL host] lowercaseString];
    } else {
        hostString = [NSString stringWithFormat:@"%@:%@", [[self.URL host] lowercaseString], [self.URL port]];
    }
    
    // Annoyingly [self.url path] is decoded and has trailing slashes stripped, so we have to manually extract the path without the query or fragment
    NSString *pathString = [[self.URL absoluteString] substringFromIndex:[[self.URL scheme] length] + 3];
    NSRange pathStart = [pathString rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
    NSRange pathEnd = [pathString rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"?#"]];
    if (pathEnd.location != NSNotFound) {
        pathString = [pathString substringWithRange:NSMakeRange(pathStart.location, pathEnd.location - pathStart.location)];
    } else {
        pathString = (pathStart.location == NSNotFound) ? @"" : [pathString substringFromIndex:pathStart.location];
    }
    
    return [NSString stringWithFormat:@"%@://%@%@", [[self.URL scheme] lowercaseString], hostString, pathString];
}

- (NSArray *)oauthPostBodyParameters
{
    if (![self HTTPBody]) {
        return nil;
    }
    NSString *strBody = [[NSString alloc] initWithData:[self HTTPBody] encoding:NSUTF8StringEncoding];
    NSArray *pairs = [strBody componentsSeparatedByString:@"&"];
    NSMutableArray *body = [NSMutableArray array];
    for (NSString *pair in pairs) {
        NSString *key, *value;
        NSRange separator = [pair rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
        if (separator.location != NSNotFound) {
            key = [[pair substringToIndex:separator.location] decodeFromURL];
            value = [[pair substringFromIndex:separator.location + 1] decodeFromURL];
        } else {
            key = [pair decodeFromURL];
            value = @"";
        }
        
        [body addObject:[NSDictionary dictionaryWithObjectsAndKeys:key, @"key", value, @"value", nil]];
    }
    
    return body;
}

- (NSArray *)oauthAdditionalParametersForMethod:(OAuthSignatureMethod)signatureMethod
{
    // For sub-classes to override
    return nil;
}

- (NSString *)oauthRequestParameterString:(NSArray *)oauthParameters
{
    NSMutableArray *parameters = [NSMutableArray array];
    
    // Decode the parameters given in the query string, and add their encoded counterparts
    NSArray *pairs = [[self.URL query] componentsSeparatedByString:@"&"];
    for (NSString *pair in pairs) {
        NSString *key, *value;
        NSRange separator = [pair rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
        if (separator.location != NSNotFound) {
            key = [[pair substringToIndex:separator.location] decodeFromURL];
            value = [[pair substringFromIndex:separator.location + 1] decodeFromURL];
        } else {
            key = [pair decodeFromURL];
            value = @"";
        }
        
        [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[key encodeForURL], @"key", [value encodeForURL], @"value", nil]];
    }
    
    // Add the encoded counterparts of the parameters in the OAuth header
    for (NSDictionary *param in oauthParameters) {
        NSString *key = [param objectForKey:@"key"];
        if ([key hasPrefix:@"oauth_"]
            && ![key isEqualToString:@"oauth_signature"])
            [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[key encodeForURL], @"key", [[param objectForKey:@"value"] encodeForURL], @"value", nil]];
    }
    
    // Add encoded counterparts of any additional parameters from the body
    NSArray *postBodyParameters = [self oauthPostBodyParameters];
    for (NSDictionary *param in postBodyParameters)
        [parameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:[[param objectForKey:@"key"] encodeForURL], @"key", [[param objectForKey:@"value"]  encodeForURL], @"value", nil]];
    
    // Sort by name and value
    [parameters sortUsingComparator:^(id obj1, id obj2) {
        NSDictionary *val1 = obj1, *val2 = obj2;
        NSComparisonResult result = [[val1 objectForKey:@"key"] compare:[val2 objectForKey:@"key"] options:NSLiteralSearch];
        if (result != NSOrderedSame)
            return result;
        
        return [[val1 objectForKey:@"value"] compare:[val2 objectForKey:@"value"] options:NSLiteralSearch];
    }];
    
    // Join components together
    NSMutableArray *parameterStrings = [NSMutableArray array];
    for (NSDictionary *parameter in parameters)
        [parameterStrings addObject:[NSString stringWithFormat:@"%@=%@", [parameter objectForKey:@"key"], [parameter objectForKey:@"value"]]];
    
    return [parameterStrings componentsJoinedByString:@"&"];
}


#pragma mark -
#pragma mark Signing algorithms

- (NSString *)oauthGeneratePlaintextSignatureFor:(NSString *)baseString
                                withClientSecret:(NSString *)clientSecret
                                  andTokenSecret:(NSString *)tokenSecret
{
    // Construct the signature key
    return [NSString stringWithFormat:@"%@&%@", clientSecret != nil ? [clientSecret encodeForURL] : @"", tokenSecret != nil ? [tokenSecret encodeForURL] : @""];
}

- (NSString *)oauthGenerateHMAC_SHA1SignatureFor:(NSString *)baseString
                                withClientSecret:(NSString *)clientSecret
                                  andTokenSecret:(NSString *)tokenSecret
{
	
    NSString *key = [self oauthGeneratePlaintextSignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
    
    const char *keyBytes = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *baseStringBytes = [baseString cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char digestBytes[CC_SHA1_DIGEST_LENGTH];
    
	CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA1, keyBytes, strlen(keyBytes));
	CCHmacUpdate(&ctx, baseStringBytes, strlen(baseStringBytes));
	CCHmacFinal(&ctx, digestBytes);
    
	NSData *digestData = [NSData dataWithBytes:digestBytes length:CC_SHA1_DIGEST_LENGTH];
    return [digestData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}


#pragma mark -
#pragma mark Public methods

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                            usingMethod:(OAuthSignatureMethod)signatureMethod
{
    [self signRequestWithClientIdentifier:clientIdentifier secret:clientSecret tokenIdentifier:tokenIdentifier
                                   secret:tokenSecret verifier:nil usingMethod:signatureMethod];
}

- (void)signRequestWithClientIdentifier:(NSString *)clientIdentifier
                                 secret:(NSString *)clientSecret
                        tokenIdentifier:(NSString *)tokenIdentifier
                                 secret:(NSString *)tokenSecret
                               verifier:(NSString *)verifier
                            usingMethod:(OAuthSignatureMethod)signatureMethod
{
    [self setValue:[self oauthTokenWithClientIdentifier:clientIdentifier secret:clientSecret tokenIdentifier:tokenIdentifier secret:tokenSecret verifier:verifier usingMethod:signatureMethod] forHTTPHeaderField:@"Authorization"];
}

- (NSString *)oauthTokenWithClientIdentifier:(NSString *)clientIdentifier
                                      secret:(NSString *)clientSecret
                             tokenIdentifier:(NSString *)tokenIdentifier
                                      secret:(NSString *)tokenSecret
                                    verifier:(NSString *)verifier
                                 usingMethod:(OAuthSignatureMethod)signatureMethod
{
    NSMutableArray *oauthParameters = [NSMutableArray array];
    
    // Add what we know now to the OAuth parameters
    //    if (self.authenticationRealm)
    //        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"realm", @"key", self.authenticationRealm, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_version", @"key", oauthVersion, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_consumer_key", @"key", clientIdentifier, @"value", nil]];
    if (tokenIdentifier != nil)
        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_token", @"key", tokenIdentifier, @"value", nil]];
    if (verifier != nil)
        [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_verifier", @"key", verifier, @"value", nil]];
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_signature_method", @"key", oauthSignatureMethodName[signatureMethod], @"value", nil]];
    [oauthParameters addObjectsFromArray:[self oauthGenerateTimestampAndNonce]];
    [oauthParameters addObjectsFromArray:[self oauthAdditionalParametersForMethod:signatureMethod]];
    
    // Construct the signature base string
    NSString *baseStringURI = [self oauthBaseStringURI];
    NSString *requestParameterString = [self oauthRequestParameterString:oauthParameters];
    NSString *baseString = [NSString stringWithFormat:@"%@&%@&%@", [[self HTTPMethod] uppercaseString], [baseStringURI encodeForURL], [requestParameterString encodeForURL]];
    
    // Generate the signature
    NSString *signature;
    switch (signatureMethod) {
        case OAuthPlaintextSignatureMethod:
            signature = [self oauthGeneratePlaintextSignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
            break;
        case OAuthHMAC_SHA1SignatureMethod:
            signature = [self oauthGenerateHMAC_SHA1SignatureFor:baseString withClientSecret:clientSecret andTokenSecret:tokenSecret];
            break;
    }
    [oauthParameters addObject:[NSDictionary dictionaryWithObjectsAndKeys:@"oauth_signature", @"key", signature, @"value", nil]];
    
    // Set the Authorization header
    NSMutableArray *oauthHeader = [NSMutableArray array];
    for (NSDictionary *param in oauthParameters)
        [oauthHeader addObject:[NSString stringWithFormat:@"%@=\"%@\"", [[param objectForKey:@"key"] encodeForURL], [[param objectForKey:@"value"] encodeForURL]]];
    return [NSString stringWithFormat:@"OAuth %@", [oauthHeader componentsJoinedByString:@", "]];
}

@end



