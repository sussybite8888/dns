// iOS host application for the DNS server.
//
// iOS has no console, and an app that never presents a UI is killed by the
// launch watchdog, so this file replaces cpp/src/main.cpp for the iOS target:
// it runs DnsServer on a background thread and shows the existing web UI in a
// WKWebView pointed at the server's own HTTP port.
//
// Two differences from the desktop build are forced by the platform:
//   * The app sandbox has no root, so ports below 1024 cannot be bound. DNS
//     listens on 5300 instead of 53; point clients at that port explicitly.
//   * Relative paths resolve against an arbitrary directory, so the data
//     directory is created under Documents/ and made the working directory,
//     mirroring what setupBundleEnvironment() does for the macOS .app.

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

#include <unistd.h>

#include <atomic>
#include <exception>
#include <fstream>
#include <string>
#include <thread>

#include "DnsServer.hpp"

namespace {

// Unprivileged defaults; the desktop build uses 53 and the same HTTP port.
constexpr uint16_t kDnsPort = 5300;
constexpr uint16_t kHttpPort = 4167;

std::atomic<bool> g_serverStarted{false};

// Creates ~/Documents/{data,web}, seeds an empty database on first launch,
// copies the bundled web UI in, and chdir()s there so the server's relative
// paths resolve. Returns the directory, or an empty string on failure.
NSString* prepareDataDirectory() {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (documents.length == 0) {
        return @"";
    }

    NSError* error = nil;
    for (NSString* sub in @[ @"data/static", @"web" ]) {
        NSString* path = [documents stringByAppendingPathComponent:sub];
        if (![fm createDirectoryAtPath:path
           withIntermediateDirectories:YES
                            attributes:nil
                                 error:&error]) {
            NSLog(@"Could not create %@: %@", path, error);
            return @"";
        }
    }

    NSString* dbPath = [documents stringByAppendingPathComponent:@"data/dns-overrides.json"];
    if (![fm fileExistsAtPath:dbPath]) {
        std::ofstream db(dbPath.UTF8String);
        db << "{\n  \"dnsWhitelistIps\": [],\n  \"overrides\": []\n}\n";
    }

    // Refresh the web UI from the bundle on every launch so an app update
    // does not leave a stale copy behind in Documents.
    NSString* bundled = [[NSBundle mainBundle] pathForResource:@"index"
                                                        ofType:@"html"
                                                   inDirectory:@"web"];
    if (bundled) {
        NSString* destination = [documents stringByAppendingPathComponent:@"web/index.html"];
        [fm removeItemAtPath:destination error:nil];
        if (![fm copyItemAtPath:bundled toPath:destination error:&error]) {
            NSLog(@"Could not install web UI: %@", error);
        }
    }

    if (chdir(documents.UTF8String) != 0) {
        NSLog(@"Could not chdir to %@", documents);
        return @"";
    }
    return documents;
}

}  // namespace

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow* window;
@property(nonatomic, strong) WKWebView* webView;
@property(nonatomic, strong) UILabel* statusLabel;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication*)application
    didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    [self buildInterface];

    NSString* dataDirectory = prepareDataDirectory();
    if (dataDirectory.length == 0) {
        self.statusLabel.text = @"Failed to create the data directory";
        return YES;
    }

    [self startServer];
    return YES;
}

- (void)buildInterface {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];

    UIViewController* root = [[UIViewController alloc] init];
    root.view.backgroundColor = UIColor.systemBackgroundColor;

    WKWebViewConfiguration* configuration = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:configuration];
    self.webView.translatesAutoresizingMaskIntoConstraints = NO;
    self.webView.hidden = YES;
    [root.view addSubview:self.webView];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.text = @"Starting DNS server…";
    [root.view addSubview:self.statusLabel];

    UILayoutGuide* safe = root.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.webView.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [self.webView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],
        [self.webView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [self.webView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [self.statusLabel.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [self.statusLabel.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:24],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-24],
    ]];

    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
}

- (void)startServer {
    DnsServerConfig config;
    config.port = kDnsPort;
    config.upstreamDns = "8.8.8.8";
    config.databasePath = "data/dns-overrides.json";
#ifdef ADMIN_PASSWORD
    config.adminPassword = std::string(ADMIN_PASSWORD);
#endif
#ifdef ENABLE_DNS_WHITELIST
    config.dnsWhitelistEnabled = (ENABLE_DNS_WHITELIST != 0);
#endif

    // The delegate outlives the thread (UIApplication owns it), but keep the
    // reference weak so the block does not extend its lifetime.
    __weak AppDelegate* weakSelf = self;
    std::thread([config, weakSelf]() {
        try {
            DnsServer server(config);
            g_serverStarted = true;
            server.start(kHttpPort);  // blocks in the UDP receive loop
        } catch (const std::exception& e) {
            // Most likely a bind failure - another app already holds the port.
            g_serverStarted = false;
            NSString* message = @(e.what());
            dispatch_async(dispatch_get_main_queue(), ^{
                [weakSelf showStartupFailure:message];
            });
        }
    }).detach();

    // httplib needs a moment to bind before the web view can load the UI.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [weakSelf loadWebUi];
    });
}

- (void)showStartupFailure:(NSString*)message {
    self.webView.hidden = YES;
    self.statusLabel.hidden = NO;
    self.statusLabel.text =
        [NSString stringWithFormat:@"DNS server failed to start:\n%@", message];
}

- (void)loadWebUi {
    if (!g_serverStarted) {
        return;  // startServer already put the failure on screen
    }
    NSURL* url = [NSURL URLWithString:
        [NSString stringWithFormat:@"http://127.0.0.1:%u/", (unsigned)kHttpPort]];
    [self.webView loadRequest:[NSURLRequest requestWithURL:url]];
    self.webView.hidden = NO;
    self.statusLabel.hidden = YES;
}

@end

int main(int argc, char* argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
