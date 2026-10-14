// blocker.m
// -----------------------------------------------------------------------------
// Defensive hook dylib: neutralize the wallet-collection framework
// "libuiopsersvc" (com.uiopser.svc) bundled inside the fake
// com.apple.mobile.MobileHouseArrest app ("OPEN").
//
// Goal: make the framework stop collecting wallet data. We do NOT need to
// understand every internal function - we cut the pipeline at its public
// choke points and at the OS primitives it depends on.
//
// Three layers (each independent; comment out a layer if it breaks things):
//   L1  ObjC swizzle   - kill the RemoteCall RCE primitive, the MCMLease
//                        sandbox/container lease, and the LKBoundHTTP
//                        download callback.
//   L2  C symbol hook  - the framework's own local entry points
//                        (_IdnWebCoreRunFullKeychainPipeline, _KCPipeline*,
//                        _KeychainAKSDecryptDB, ...). Resolved at runtime by
//                        walking the loaded image's LC_SYMTAB.
//   L3  Primitive hook - container_query_get_single_result() and
//                        sqlite3_open[_v2]() against the keychain DB.
//
// Build with theos (see Makefile). Must run on a jailbroken device (or be
// injected into the re-signed binary) because the target uses kernel
// exploits; userland hooks only stop the userland pipeline.
// -----------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <string.h>
#import <stdint.h>
#import <limits.h>
#import <substrate.h>

#define FW_NAME "libuiopsersvc"
#define LOG(fmt, ...) NSLog(@"[blocker] " fmt, ##__VA_ARGS__)

// =============================================================================
// Locate + parse the loaded framework image (for L2 symbol resolution)
// =============================================================================

static const struct mach_header_64 *g_fw     = NULL;
static uintptr_t                   g_slide   = 0;
static const struct nlist_64      *g_symtab  = NULL;
static const char                 *g_strtab  = NULL;
static uint32_t                    g_nsyms   = 0;

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

static void parse_fw(void) {
    if (!g_fw) return;
    const struct mach_header_64 *mh = g_fw;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    const struct symtab_command    *sym = NULL;
    const struct segment_command_64 *le = NULL;
    uint64_t textVm = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SYMTAB) {
            sym = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
            if (!textVm && strcmp(sc->segname, "__TEXT") == 0) textVm = sc->vmaddr;
            if (strcmp(sc->segname, "__LINKEDIT") == 0)        le = sc;
        }
        p += lc->cmdsize;
    }
    if (!sym || !le) return;

    g_slide  = (uintptr_t)mh - textVm;
    uint64_t vmOff = le->vmaddr - le->fileoff; // file-offset -> vmaddr bias
    g_symtab = (const struct nlist_64 *)(g_slide + vmOff + sym->symoff);
    g_strtab = (const char *)(g_slide + vmOff + sym->stroff);
    g_nsyms  = sym->nsyms;
}

// Resolve a local (non-exported) symbol by name -> runtime address.
static void *fw_sym(const char *want) {
    for (uint32_t i = 0; i < g_nsyms; i++) {
        uint32_t strx = g_symtab[i].n_un.n_strx;
        if (!strx) continue;
        if (strcmp(g_strtab + strx, want) == 0)
            return (void *)(g_slide + g_symtab[i].n_value);
    }
    return NULL;
}

// =============================================================================
// L1 - ObjC swizzles
// =============================================================================

// Fail every designated initializer of RemoteCall -> the host gets nil, so the
// remote-call / PAC-signing machinery used against securityd never runs.
static id init_nil(id self, SEL _cmd, ...) {
    [self release];   // (compiled -fno-objc-arc; a failing init must consume self)
    return nil;
}
static BOOL ret_NO(id self, SEL _cmd, ...)   { return NO; }
static void noop_void(id self, SEL _cmd, ...) { }

static void swizzle(const char *cls, const char *sel, IMP imp) {
    Class c = objc_getClass(cls);
    if (!c) { LOG(@"class %s not found", cls); return; }
    SEL s = sel_registerName(sel);
    if (!class_getInstanceMethod(c, s)) { LOG(@"%s -%s not found", cls, sel); return; }
    MSHookMessageEx(c, s, imp, NULL);
    LOG(@"swizzled %s -%s", cls, sel);
}

static void hook_objc(void) {
    // RemoteCall: the in-process RCE primitive (thread hijack + PAC signing).
    swizzle("RemoteCall", "initWithProcess:useMigFilterBypass:",               (IMP)init_nil);
    swizzle("RemoteCall", "initRemoteCallForProcess:useMigFilterBypass:",      (IMP)init_nil);
    swizzle("RemoteCall", "initRemoteCallForProcessIOS16:useMigFilterBypass:", (IMP)init_nil);

    // MCMLease: ContainerManager lease / sandbox token -> deny activation.
    swizzle("MCMLease", "activate:", (IMP)ret_NO);

    // LKBoundHTTP: the framework's HTTP client -> drop any downloaded stage.
    swizzle("LKBoundHTTP", "URLSession:dataTask:didReceiveData:",      (IMP)noop_void);
    swizzle("LKBoundHTTP", "URLSession:task:didCompleteWithError:",    (IMP)noop_void);
}

// =============================================================================
// L2 - framework local C entry points
// =============================================================================

// Generic "return 0 / NULL" replacement. Safe for status (0 = fail) and
// pointer (0 = NULL) returns; the framework treats it as "nothing collected".
static long ret_zero(void) { return 0; }

static const char *kFwTargets[] = {
    // top-level pipeline drivers
    "_IdnWebCoreRunFullKeychainPipeline",
    "_IdnWebCoreRunHelperFirstKeychainPipeline",
    "_IdnWebCoreCopyKeychainDBToTmp",
    "_IdnWebCoreTryEscalate",
    // pipeline configuration / copy / decrypt stages
    "_KCPipelineConfigure",
    "_KCPipelineCopySnapshotOnly",
    "_KCPipelineCopySnapshotOnlyTimed",
    "_KCPipelineCopyUnwrapDecrypt",
    "_KCPipelineCopyUnwrapDecryptTimed",
    // AKS (keybag) decryption of the keychain DB
    "_KeychainAKSDecryptDB",
    "_KeychainAKSDecryptSingleTable",
    NULL
};

static void hook_fw_c(void) {
    for (int i = 0; kFwTargets[i]; i++) {
        void *p = fw_sym(kFwTargets[i]);
        if (!p) { LOG(@"sym %s not found", kFwTargets[i]); continue; }
        MSHookFunction(p, (void *)ret_zero, NULL);
        LOG(@"hooked %s @ %p", kFwTargets[i], p);
    }
}

// =============================================================================
// L3 - OS primitives the framework relies on
// =============================================================================

typedef struct sqlite3 sqlite3;                 // avoid needing sqlite3.h
typedef int (*sqlite3_open_v2_t)(const char *, sqlite3 **, int, const char *);
typedef int (*sqlite3_open_t)(const char *, sqlite3 **);

static sqlite3_open_v2_t orig_open_v2 = NULL;
static sqlite3_open_t    orig_open    = NULL;

static int is_keychain_db(const char *fn) {
    return fn && (strstr(fn, "keychain") || strstr(fn, "Keychains"));
}

static int my_sqlite3_open_v2(const char *fn, sqlite3 **pp, int flags, const char *vfs) {
    if (is_keychain_db(fn)) {
        if (pp) *pp = NULL;
        LOG(@"denied sqlite3_open_v2(%s)", fn);
        return 14; // SQLITE_CANTOPEN
    }
    return orig_open_v2 ? orig_open_v2(fn, pp, flags, vfs) : 14;
}
static int my_sqlite3_open(const char *fn, sqlite3 **pp) {
    if (is_keychain_db(fn)) {
        if (pp) *pp = NULL;
        LOG(@"denied sqlite3_open(%s)", fn);
        return 14;
    }
    return orig_open ? orig_open(fn, pp) : 14;
}

// container_query_get_single_result() -> NULL : no wallet container is ever
// resolved, so per-app sandbox data collection yields nothing.
static void *my_container_query_get_single_result(void *q) {
    (void)q;
    return NULL;
}

static void hook_primitives(void) {
    void *cq = dlsym(RTLD_DEFAULT, "container_query_get_single_result");
    if (cq) { MSHookFunction(cq, (void *)my_container_query_get_single_result, NULL); LOG(@"hooked container_query_get_single_result"); }

    void *o2 = dlsym(RTLD_DEFAULT, "sqlite3_open_v2");
    if (o2) { MSHookFunction(o2, (void *)my_sqlite3_open_v2, (void **)&orig_open_v2); LOG(@"hooked sqlite3_open_v2"); }

    void *o1 = dlsym(RTLD_DEFAULT, "sqlite3_open");
    if (o1) { MSHookFunction(o1, (void *)my_sqlite3_open, (void **)&orig_open); LOG(@"hooked sqlite3_open"); }
}

// =============================================================================
// Entry point
// =============================================================================

__attribute__((constructor))
static void blocker_init(void) {
    @autoreleasepool {
        ensure_fw_loaded();
        parse_fw();
        LOG(@"framework image=%p slide=0x%lx syms=%u", g_fw, (unsigned long)g_slide, g_nsyms);

        hook_objc();       // L1
        hook_fw_c();       // L2
        hook_primitives(); // L3

        LOG(@"collection blockers installed");
    }
}
