/* Optional NetworkStatistics adapter. Only metadata crosses this boundary. */
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

struct iotap_network_sample {
    uint64_t source, started, process, received, sent;
    int32_t pid;
    uint32_t interface, protocol, flags;
    uint8_t local[28], remote[28];
};

typedef void (*observer)(void *, const struct iotap_network_sample *);
struct collector;
struct source {
    struct source *next;
    struct collector *owner;
    void *ref;
    uint64_t id;
    CFMutableDictionaryRef values;
};

struct collector {
    void *library, *manager;
    dispatch_queue_t queue;
    dispatch_source_t timer;
    observer observe;
    void *context;
    struct source *sources;
    uint64_t next_id;
    void (*destroy)(void *);
    void (*query)(void *, void (^)(void));
    void (*description)(void *, void (^)(CFDictionaryRef));
    void (*counts)(void *, void (^)(CFDictionaryRef));
    void (*removed)(void *, void (^)(void));
    void (*query_description)(void *);
    int stopping, pending;
};

int iotap_network_stop(void *handle);

static int number(CFDictionaryRef dict, CFStringRef key, uint64_t *out) {
    CFTypeRef value = CFDictionaryGetValue(dict, key);
    return value && CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue(value, kCFNumberSInt64Type, out);
}

static void address(CFDictionaryRef dict, CFStringRef key, uint8_t out[28]) {
    CFTypeRef value = CFDictionaryGetValue(dict, key);
    if (value && CFGetTypeID(value) == CFDataGetTypeID()) {
        CFIndex len = CFDataGetLength(value);
        if (len == 16 || len == 28) memcpy(out, CFDataGetBytePtr(value), (size_t)len);
    }
}

static void merge(const void *key, const void *value, void *dict) {
    CFDictionarySetValue(dict, key, value);
}

static void emit(struct source *source, CFDictionaryRef changes, int closed) {
    struct collector *c = source->owner;
    if (changes && CFGetTypeID(changes) == CFDictionaryGetTypeID())
        CFDictionaryApplyFunction(changes, merge, source->values);
    CFDictionaryRef d = source->values;
    struct iotap_network_sample s = {.source = source->id, .flags = closed ? 1u : 0u};
    uint64_t pid = 0, interface = 0;
    if (!number(d, CFSTR("processID"), &pid) || !number(d, CFSTR("uniqueProcessID"), &s.process) ||
        !number(d, CFSTR("rxBytes"), &s.received) || !number(d, CFSTR("txBytes"), &s.sent)) return;
    s.pid = (int32_t)pid;
    number(d, CFSTR("startAbsoluteTime"), &s.started);
    number(d, CFSTR("interface"), &interface);
    s.interface = (uint32_t)interface;
    CFTypeRef provider = CFDictionaryGetValue(d, CFSTR("provider"));
    if (provider && CFEqual(provider, CFSTR("TCP"))) s.protocol = 6;
    else if (provider && CFEqual(provider, CFSTR("UDP"))) s.protocol = 17;
    else return;
    address(d, CFSTR("localAddress"), s.local);
    address(d, CFSTR("remoteAddress"), s.remote);
    c->observe(c->context, &s);
}

static void added(struct collector *c, void *ref) {
    if (c->stopping) return;
    struct source *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->owner = c;
    s->ref = ref;
    s->id = ++c->next_id;
    s->values = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    s->next = c->sources;
    c->sources = s;
    c->description(ref, ^(CFDictionaryRef d) {
        if (d && CFGetTypeID(d) == CFDictionaryGetTypeID())
            CFDictionaryApplyFunction(d, merge, s->values);
    });
    c->counts(ref, ^(CFDictionaryRef d) { emit(s, d, 0); });
    c->removed(ref, ^{
        emit(s, NULL, 1);
        struct source **link = &c->sources;
        while (*link && *link != s) link = &(*link)->next;
        if (*link) *link = s->next;
        CFRelease(s->values);
        free(s);
    });
    c->query_description(ref);
}

/* NULL means that this OS does not provide the required optional interface. */
void *iotap_network_start(observer observe, void *context) {
    struct collector *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->library = dlopen("/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics", RTLD_NOW | RTLD_LOCAL);
    if (!c->library) { free(c); return NULL; }
    void *(*create)(CFAllocatorRef, dispatch_queue_t, void (^)(void *)) = dlsym(c->library, "NStatManagerCreate");
    int (*tcp)(void *, uint64_t) = dlsym(c->library, "NStatManagerAddAllTCPWithFilter");
    int (*udp)(void *, uint64_t) = dlsym(c->library, "NStatManagerAddAllUDPWithFilter");
    c->destroy = dlsym(c->library, "NStatManagerDestroy");
    c->query = dlsym(c->library, "NStatManagerQueryAllSourcesUpdate");
    c->description = dlsym(c->library, "NStatSourceSetDescriptionBlock");
    c->counts = dlsym(c->library, "NStatSourceSetCountsBlock");
    c->removed = dlsym(c->library, "NStatSourceSetRemovedBlock");
    c->query_description = dlsym(c->library, "NStatSourceQueryDescription");
    if (!create || !tcp || !udp || !c->destroy || !c->query || !c->description || !c->counts || !c->removed || !c->query_description) {
        dlclose(c->library); free(c); return NULL;
    }
    c->observe = observe;
    c->context = context;
    c->queue = dispatch_queue_create("iotap.network-statistics", DISPATCH_QUEUE_SERIAL);
    c->manager = create(NULL, c->queue, ^(void *source) { added(c, source); });
    if (!c->manager) { dispatch_release(c->queue); dlclose(c->library); free(c); return NULL; }
    int subscribed = tcp(c->manager, 0) && udp(c->manager, 0);
    c->timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, c->queue);
    dispatch_source_set_timer(c->timer, DISPATCH_TIME_NOW, NSEC_PER_SEC, NSEC_PER_MSEC * 25);
    dispatch_source_set_event_handler(c->timer, ^{
        if (!c->stopping && !c->pending) {
            c->pending = 1;
            c->query(c->manager, ^{
                c->pending = 0;
                struct iotap_network_sample s = {.flags = 2};
                c->observe(c->context, &s);
            });
        }
    });
    dispatch_resume(c->timer);
    if (!subscribed) { iotap_network_stop(c); return NULL; }
    return c;
}

/* The caller keeps the observer context alive until this returns. */
int iotap_network_stop(void *handle) {
    struct collector *c = handle;
    dispatch_source_cancel(c->timer);
    dispatch_sync(c->queue, ^{ c->stopping = 1; });
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    /* A completion that arrives after the deadline must still own its semaphore. */
    dispatch_retain(done);
    c->query(c->manager, ^{ dispatch_semaphore_signal(done); dispatch_release(done); });
    int incomplete = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) != 0;
    c->destroy(c->manager);
    dispatch_sync(c->queue, ^{});
    while (c->sources) {
        struct source *s = c->sources;
        c->sources = s->next;
        CFRelease(s->values);
        free(s);
    }
    dispatch_release(done);
    dispatch_release(c->timer);
    dispatch_release(c->queue);
    /* Framework blocks can outlive the manager. Keep its code mapped. */
    free(c);
    return incomplete;
}

uint64_t iotap_network_process(int pid) {
    /* PROC_PIDUNIQIDENTIFIERINFO (XNU sys/proc_info_private.h). This 56-byte
       structure is a fixed API even though the SDK does not expose its declaration. */
    struct {
        uint8_t uuid[16];
        uint64_t uniqueid, parent;
        int32_t version, parent_version;
        uint64_t reserved[2];
    } info;
    _Static_assert(sizeof(info) == 56, "process identity ABI");
    int n = proc_pidinfo(pid, 17, 0, &info, sizeof(info));
    return n == (int)sizeof(info) ? info.uniqueid : 0;
}

size_t iotap_network_sample_size(void) { return sizeof(struct iotap_network_sample); }
