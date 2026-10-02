/* A silent Foundation client for the macOS network-statistics live check. */
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <unistd.h>

static int has_channel(void) {
    struct proc_fdinfo fds[256];
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    for (int i = 0; i < bytes / (int)sizeof(fds[0]); i++)
        if (fds[i].proc_fdtype == PROX_FDTYPE_CHANNEL) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    alarm(40);
    @autoreleasepool {
        NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        config.timeoutIntervalForRequest = 6;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:argv[1]]];
        puts("ready"); fflush(stdout);
        sleep(3); /* Let iotap subscribe before the first connection is made. */
        for (int i = 0; i < 4; i++) {
            dispatch_semaphore_t done = dispatch_semaphore_create(0);
            __block NSUInteger size = 0;
            NSURLSessionDataTask *task = [session dataTaskWithURL:url completionHandler:
                ^(NSData *data, NSURLResponse *response, NSError *error) {
                    (void)response;
                    if (!error) size = data.length;
                    dispatch_semaphore_signal(done);
                }];
            [task resume];
            if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC))) return 3;
            printf("received=%lu channel=%d\n", (unsigned long)size, has_channel()); fflush(stdout);
            if (!size) return 4;
            usleep(300000);
        }
        sleep(10); /* Keep counters available for the comparison with nettop. */
        [session invalidateAndCancel];
    }
    return 0;
}
