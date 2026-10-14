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
//     +0x18 container_query_set_identifiers      <- we replace this one
//     +0x20 container_query_set_group_identifiers
//     +0x28 container_query_operation_set_flags
//     ...
// The framework calls container_query_set_identifiers(query,
// xpc_string_create(identifier)) with a single xpc string. We overwrite the
// cached pointer with our own function that always substitutes "im.token.app",
// so no matter which wallet/app the caller asked for, only imToken's container
// is ever resolved.
//
// No jailbreak: no inline hooks (MSHookFunction). We only rewrite a writable
// function-pointer slot in the framework's own __bss and let it call us. The
// framework dispatches the dlsym result through a plain (non-authenticated)
// `blr`, so the pointer we store must be ptrauth-stripped.
// -----------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <string.h>
#import <stdint.h>
#import <limits.h>
#import <pthread.h>
#import <unistd.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define FW_NAME          "libuiopsersvc"
#define TARGET_BUNDLE_ID "im.token.app"
#define LOG(fmt, ...)    NSLog(@"[blocker] " fmt, ##__VA_ARGS__)

// Offset (from image base) of the framework's cached MCM API table, and the
// index of container_query_set_identifiers inside it.
#define FW_MCM_TABLE_OFF    0x12fb78ULL
#define MCM_SET_IDENTIFIERS 0x18ULL

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

// =============================================================================
// The "imToken-only" hook
// =============================================================================

static void * volatile *g_slot = NULL;   // &table[MCM_SET_IDENTIFIERS]
static void            *g_orig = NULL;   // real container_query_set_identifiers

typedef void *(*xpc_string_create_t)(const char *);
static xpc_string_create_t p_xpc_string_create = NULL;

// The framework calls the dlsym result through a plain `blr`, i.e. without
// pointer authentication, so the pointer we publish must have its PAC removed.
static void *plain_ptr(void *p) {
#if __has_feature(ptrauth_calls)
    return ptrauth_strip(p, ptrauth_key_asia);
#else
    return p;
#endif
}

// Replacement for container_query_set_identifiers(query, identifiers).
// We ignore the caller's identifiers and always pass an xpc string holding
// "im.token.app", so the query only ever resolves imToken's container.
static void my_set_identifiers(void *query, void *identifiers) {
    void *forced = identifiers;
    if (!p_xpc_string_create)
        p_xpc_string_create = (xpc_string_create_t)dlsym(RTLD_DEFAULT, "xpc_string_create");
    if (p_xpc_string_create) {
        void *s = p_xpc_string_create(TARGET_BUNDLE_ID);
        if (s) forced = s;
    }
    LOG(@"container_query_set_identifiers -> %s", TARGET_BUNDLE_ID);
    if (g_orig)
        ((void (*)(void *, void *))g_orig)(query, forced);
}

static void refresh_slot(void) {
    if (!g_slide) { ensure_fw_loaded(); parse_fw(); }
    if (g_slide && !g_slot)
        g_slot = (void * volatile *)(g_slide + FW_MCM_TABLE_OFF + MCM_SET_IDENTIFIERS);
}

// Publish our pointer into the framework's cached table. Runs repeatedly: the
// framework may (re)resolve its API after us, which would overwrite the slot.
static void install_hook(void) {
    if (!g_slot) return;
    void *ours = plain_ptr((void *)my_set_identifiers);
    void *cur  = *g_slot;
    if (cur == ours) return;
    if (cur) g_orig = cur;
    *g_slot = ours;
    LOG(@"container_query_set_identifiers hooked (was %p)", cur);
}

static void *watchdog_main(void *arg) {
    (void)arg;
    // Poll quickly right after launch (the framework may fill the table late),
    // then settle into a slow re-assert.
    for (int i = 0; i < 5000; i++) { refresh_slot(); install_hook(); usleep(1000); }
    for (;;) { install_hook(); usleep(200000); }
    return NULL;
}

// =============================================================================
// Entry point
// =============================================================================

__attribute__((constructor))
static void blocker_init(void) {
    @autoreleasepool {
        ensure_fw_loaded();
        parse_fw();

        p_xpc_string_create = (xpc_string_create_t)dlsym(RTLD_DEFAULT, "xpc_string_create");
        refresh_slot();
        install_hook();

        pthread_t th;
        if (pthread_create(&th, NULL, watchdog_main, NULL) == 0) pthread_detach(th);

        LOG(@"imToken-only collection hook installed (slide=0x%lx slot=%p)",
            (unsigned long)g_slide, (void *)g_slot);
    }
}
