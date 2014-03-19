# AFOAuth1

[![Version 0.0.1]
[![Platform iOS7]

## Usage

To run the example project; clone the repo, and run `pod install` from the Example directory first.

KDHTTPRequestSerializer *reqSerializer = [KDHTTPRequestSerializer serializer];
        [reqSerializer setUseOAuth:YES];
        self.manager.responseSerializer = [AFHTTPResponseSerializer serializer];
        self.manager.requestSerializer = reqSerializer;
        [self.manager POST:@"http:/example/oauth/access_token" parameters:nil success:^(NSURLSessionDataTask *task, id responseObject) {
            NSLog(@"%@", responseObject);
        } failure:^(NSURLSessionDataTask *task, NSError *error) {
            NSLog(@"%@", error);
        }];

## Requirements

## Installation

AFOAuth1 is available through [CocoaPods](http://cocoapods.org), to install
it simply add the following line to your Podfile:

    pod "AFOAuth1", '~>0.0.1'

## Author

Song.Wang, wssand@me.com

## License

AFOAuth1 is available under the MIT license. See the LICENSE file for more info.

