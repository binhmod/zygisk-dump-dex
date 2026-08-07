// =========================================================================
// main.cpp — Zygisk-Loader payload dùng LSPlant để hook 10 dispatcher
// F5e5d2631_00 đến F5e5d2631_09 (VirBox, xác nhận cấu trúc từ
// m5e5d2631.smali đã dump được trước đó).
//
// KIẾN TRÚC ĐÚNG THEO API LSPLANT THẬT:
//   jobject Hook(JNIEnv*, jobject target_method, jobject hooker_object,
//                jobject callback_method);
// callback_method PHẢI LÀ 1 java.lang.reflect.Method object thật, chữ ký
// Java "public Object callback(Object[] args)" — không phải function
// pointer C++ thuần.
//
// Giải pháp: biên dịch sẵn 1 class Java (HookStub, xem java_stub/) chứa
// 10 method callback đúng chữ ký, đóng gói thành .dex, NHÚNG bytes của
// .dex đó vào file .cpp này (build-time), rồi lúc runtime dùng
// InMemoryDexClassLoader nạp nó từ bytes trong bộ nhớ.
// =========================================================================

#include <jni.h>
#include <android/log.h>
#include <dobby.h>
#include <lsplant.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <chrono>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <cstring>
#include <cstdint>

#include "hook_stub_dex.h"

#define LOG_TAG "dump_dex_cpp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static std::string get_package_name() {
    std::ifstream f("/proc/self/cmdline");
    std::string cmdline;
    std::getline(f, cmdline, '\0');
    return cmdline.empty() ? "unknown" : cmdline;
}

static void dbg_log(const std::string &msg) {
    std::string pkg = get_package_name();
    std::string dir = "/data/data/" + pkg + "/files";
    mkdir(dir.c_str(), 0755);
    std::string path = dir + "/dump_dex_debug.log";

    std::ofstream logf(path, std::ios::app);
    if (logf.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        logf << "[" << ms << "] pid=" << getpid() << " " << msg << "\n";
    }
    LOGI("%s", msg.c_str());
}

static void log_method_call(int dispatcher_idx, jint method_id) {
    std::string pkg = get_package_name();
    std::string dir = "/data/data/" + pkg + "/dexes";
    mkdir(dir.c_str(), 0755);
    std::string path = dir + "/method_calls.log";

    std::ofstream logf(path, std::ios::app);
    if (logf.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        logf << "[" << ms << "] F_" << dispatcher_idx
             << " methodId=" << method_id << "\n";
    }
}

static void *InlineHooker(void *target, void *hooker) {
    void *backup = nullptr;
    if (DobbyHook(target, hooker, &backup) == 0) {
        return backup;
    }
    return nullptr;
}

static bool InlineUnhooker(void *func) {
    return DobbyDestroy(func) == 0;
}

// ---------------------------------------------------------------------------
// ART symbol resolvers for lsplant::InitInfo
//
// LSPlant requires BOTH a resolver that returns the exact symbol address and a
// prefix resolver. We resolve from the already-loaded libart.so (the running
// ART runtime) instead of depending on lsparself (a separate build dep that
// LSPlant's test module uses but we do not vendor).
// ---------------------------------------------------------------------------

static void *ArtSymbolResolver(std::string_view symbol) {
    static void *art_handle = []() -> void * {
        // libart.so is already loaded by the running process; dlopen just
        // bumps the refcount. Keep the handle cached for the whole session.
        return dlopen("libart.so", RTLD_NOW | RTLD_GLOBAL);
    }();
    if (art_handle == nullptr) {
        return nullptr;
    }
    return dlsym(art_handle, symbol.data());
}

// Finds the load bias (base address) of libart.so in the current process.
static uintptr_t FindLibartBase() {
    static uintptr_t base = []() -> uintptr_t {
        uintptr_t found = 0;
        dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
            if (info->dlpi_name == nullptr || *info->dlpi_name == '\0') {
                return 0;
            }
            std::string_view name(info->dlpi_name);
            if (name.find("libart.so") == std::string_view::npos) {
                return 0;
            }
            *static_cast<uintptr_t *>(data) = info->dlpi_addr;
            return 1;
        }, &found);
        return found;
    }();
    return base;
}

// Resolves the first .dynsym symbol in libart.so whose name starts with the
// given prefix (LSPlant's art_symbol_prefix_resolver contract).
static void *ArtSymbolPrefixResolver(std::string_view prefix) {
    uintptr_t base = FindLibartBase();
    if (base == 0 || prefix.empty()) {
        return nullptr;
    }

    auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shentsize == 0) {
        return nullptr;
    }

    auto *shdrs = reinterpret_cast<const ElfW(Shdr) *>(base + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const ElfW(Shdr) &sh = shdrs[i];
        if (sh.sh_type != SHT_DYNSYM) {
            continue;
        }
        auto *symtab = reinterpret_cast<const ElfW(Sym) *>(base + sh.sh_addr);
        auto *strtab = reinterpret_cast<const char *>(base + shdrs[sh.sh_link].sh_addr);
        if (symtab == nullptr || strtab == nullptr) {
            continue;
        }
        size_t count = sh.sh_size / sh.sh_entsize;
        for (size_t j = 0; j < count; j++) {
            const ElfW(Sym) &sym = symtab[j];
            if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
                continue;
            }
            const char *name = strtab + sym.st_name;
            if (std::strncmp(name, prefix.data(), prefix.size()) == 0) {
                return reinterpret_cast<void *>(base + sym.st_value);
            }
        }
    }
    return nullptr;
}

// Scans the given loaded module's .dynsym for an exact symbol name.
static void *ScanModuleSymbol(uintptr_t base, const char *want) {
    if (base == 0 || want == nullptr || *want == '\0') {
        return nullptr;
    }
    auto *ehdr = reinterpret_cast<const ElfW(Ehdr) *>(base);
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shentsize == 0) {
        return nullptr;
    }
    auto *shdrs = reinterpret_cast<const ElfW(Shdr) *>(base + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const ElfW(Shdr) &sh = shdrs[i];
        if (sh.sh_type != SHT_DYNSYM) {
            continue;
        }
        auto *symtab = reinterpret_cast<const ElfW(Sym) *>(base + sh.sh_addr);
        auto *strtab = reinterpret_cast<const char *>(base + shdrs[sh.sh_link].sh_addr);
        if (symtab == nullptr || strtab == nullptr) {
            continue;
        }
        size_t count = sh.sh_size / sh.sh_entsize;
        for (size_t j = 0; j < count; j++) {
            const ElfW(Sym) &sym = symtab[j];
            if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) {
                continue;
            }
            if (std::strcmp(strtab + sym.st_name, want) == 0) {
                return reinterpret_cast<void *>(base + sym.st_value);
            }
        }
    }
    return nullptr;
}

// Finds an exact exported symbol in ANY loaded shared library.
static void *ResolveSymbolAnywhere(const char *name) {
    if (name == nullptr) {
        return nullptr;
    }
    struct Match {
        const char *name;
        void *addr;
    } match{name, nullptr};
    dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
        auto *m = static_cast<Match *>(data);
        if (info->dlpi_name == nullptr || *info->dlpi_name == '\0' ||
            info->dlpi_addr == 0) {
            return 0;
        }
        void *addr = ScanModuleSymbol(info->dlpi_addr, m->name);
        if (addr != nullptr) {
            m->addr = addr;
            return 1;
        }
        return 0;
    }, &match);
    return match.addr;
}


static jobject g_backup_methods[10] = {nullptr};

extern "C" JNIEXPORT jobject JNICALL
Java_dump_dex_hook_HookStub_onDispatcherCalled(
    JNIEnv *env, jclass, jint dispatcher_idx, jobjectArray args) {

    jint method_id = -1;
    if (args != nullptr && env->GetArrayLength(args) > 0) {
        jobject first = env->GetObjectArrayElement(args, 0);
        if (first != nullptr) {
            jclass integer_class = env->FindClass("java/lang/Integer");
            jmethodID int_value = env->GetMethodID(integer_class, "intValue", "()I");
            method_id = env->CallIntMethod(first, int_value);
            env->DeleteLocalRef(first);
            env->DeleteLocalRef(integer_class);
        }
    }

    log_method_call(dispatcher_idx, method_id);

    jobject backup = g_backup_methods[dispatcher_idx];
    if (backup == nullptr) {
        dbg_log("onDispatcherCalled: no backup method for idx=" + std::to_string(dispatcher_idx));
        return nullptr;
    }

    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID invoke_id = env->GetMethodID(
        method_class, "invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

    jobject result = env->CallObjectMethod(backup, invoke_id, nullptr, args);

    if (env->ExceptionCheck()) {
        dbg_log("onDispatcherCalled idx=" + std::to_string(dispatcher_idx) +
                ": exception during backup invoke, clearing");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    return result;
}

static jclass load_hook_stub_class(JNIEnv *env) {
    jobject byte_buffer = env->NewDirectByteBuffer(
        const_cast<unsigned char *>(kHookStubDex), kHookStubDexLen);
    if (byte_buffer == nullptr) {
        dbg_log("NewDirectByteBuffer failed");
        return nullptr;
    }

    jclass loader_class = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (loader_class == nullptr) {
        env->ExceptionClear();
        dbg_log("InMemoryDexClassLoader class not found");
        return nullptr;
    }

    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID get_system_cl = env->GetStaticMethodID(
        class_loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject parent_cl = env->CallStaticObjectMethod(class_loader_class, get_system_cl);

    jmethodID ctor = env->GetMethodID(
        loader_class, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dex_class_loader = env->NewObject(loader_class, ctor, byte_buffer, parent_cl);

    if (dex_class_loader == nullptr || env->ExceptionCheck()) {
        dbg_log("InMemoryDexClassLoader construction failed");
        env->ExceptionClear();
        return nullptr;
    }

    jmethodID load_class = env->GetMethodID(
        loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring class_name = env->NewStringUTF("dump.dex.hook.HookStub");
    auto hook_stub_class = (jclass) env->CallObjectMethod(dex_class_loader, load_class, class_name);

    if (hook_stub_class == nullptr || env->ExceptionCheck()) {
        dbg_log("loadClass(HookStub) failed");
        env->ExceptionClear();
        return nullptr;
    }

    JNINativeMethod native_methods[] = {
        {"onDispatcherCalled", "(I[Ljava/lang/Object;)Ljava/lang/Object;",
         reinterpret_cast<void *>(&Java_dump_dex_hook_HookStub_onDispatcherCalled)},
    };
    if (env->RegisterNatives(hook_stub_class, native_methods, 1) != JNI_OK) {
        dbg_log("RegisterNatives for HookStub failed");
        env->ExceptionClear();
        return nullptr;
    }

    dbg_log("HookStub.dex loaded and native method registered successfully");
    return hook_stub_class;
}

static jobject get_callback_method(JNIEnv *env, jclass hook_stub_class, int idx) {
    char name_buf[32];
    snprintf(name_buf, sizeof(name_buf), "callback_%02d", idx);

    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared_method = env->GetMethodID(
        class_class, "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");

    jstring method_name = env->NewStringUTF(name_buf);

    jclass object_array_class = env->FindClass("[Ljava/lang/Object;");
    jobjectArray param_types = env->NewObjectArray(1, class_class, object_array_class);

    jobject method = env->CallObjectMethod(
        hook_stub_class, get_declared_method, method_name, param_types);

    if (method == nullptr || env->ExceptionCheck()) {
        dbg_log(std::string("getDeclaredMethod(") + name_buf + ") failed");
        env->ExceptionClear();
        return nullptr;
    }
    return method;
}

static jobject find_target_dispatcher_method(JNIEnv *env, jclass target_class, int idx) {
    char name_buf[32];
    snprintf(name_buf, sizeof(name_buf), "F5e5d2631_%02d", idx);
    std::string method_name(name_buf);

    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared_methods = env->GetMethodID(
        class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    auto methods_array = (jobjectArray) env->CallObjectMethod(target_class, get_declared_methods);

    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");

    jobject found = nullptr;
    jsize count = env->GetArrayLength(methods_array);
    for (jsize i = 0; i < count; i++) {
        jobject m = env->GetObjectArrayElement(methods_array, i);
        auto name_jstr = (jstring) env->CallObjectMethod(m, get_name);
        const char *name_cstr = env->GetStringUTFChars(name_jstr, nullptr);
        bool match = (method_name == name_cstr);
        env->ReleaseStringUTFChars(name_jstr, name_cstr);
        env->DeleteLocalRef(name_jstr);

        if (match) {
            found = m;
            break;
        }
        env->DeleteLocalRef(m);
    }
    return found;
}

static bool hook_one_dispatcher(JNIEnv *env, jclass target_class, jclass hook_stub_class, int idx) {
    char name_buf[32];
    snprintf(name_buf, sizeof(name_buf), "F5e5d2631_%02d", idx);

    jobject target_method = find_target_dispatcher_method(env, target_class, idx);
    if (target_method == nullptr) {
        dbg_log(std::string(name_buf) + " not found in m5e5d2631 declared methods");
        return false;
    }

    jobject callback_method = get_callback_method(env, hook_stub_class, idx);
    if (callback_method == nullptr) {
        dbg_log(std::string(name_buf) + ": callback method lookup failed");
        env->DeleteLocalRef(target_method);
        return false;
    }

    dbg_log(std::string("!!! FOUND ") + name_buf + ", hooking via LSPlant !!!");

    jobject backup = lsplant::Hook(env, target_method, nullptr, callback_method);

    env->DeleteLocalRef(target_method);
    env->DeleteLocalRef(callback_method);

    if (backup == nullptr) {
        dbg_log(std::string(name_buf) + " lsplant::Hook FAILED");
        return false;
    }

    g_backup_methods[idx] = env->NewGlobalRef(backup);
    dbg_log(std::string(name_buf) + " hooked successfully via LSPlant");
    return true;
}

static void hook_all_dispatchers(JNIEnv *env) {
    jclass target_class = env->FindClass("m5e5d2631");
    if (target_class == nullptr) {
        env->ExceptionClear();
        dbg_log("class m5e5d2631 not found (chưa load hoặc obfuscate khác tên trên build này)");
        return;
    }

    jclass hook_stub_class = load_hook_stub_class(env);
    if (hook_stub_class == nullptr) {
        dbg_log("load_hook_stub_class failed, cannot proceed");
        return;
    }

    int success_count = 0;
    for (int i = 0; i < 10; i++) {
        if (hook_one_dispatcher(env, target_class, hook_stub_class, i)) {
            success_count++;
        }
    }
    dbg_log("hook_all_dispatchers done: " + std::to_string(success_count) + "/10 succeeded");
}

static JNIEnv *get_jni_env() {
    typedef jint (*GetCreatedJavaVMs_t)(JavaVM **, jsize, jsize *);

    // JNI_GetCreatedJavaVMs is exported by a runtime library (ART/libnativehelper)
    // of the running process. Resolve it by scanning every loaded module's .dynsym
    // (most reliable), falling back to a global dlsym lookup.
    static GetCreatedJavaVMs_t GetCreatedJavaVMs =
        reinterpret_cast<GetCreatedJavaVMs_t>(ResolveSymbolAnywhere("JNI_GetCreatedJavaVMs"));

    if (GetCreatedJavaVMs == nullptr) {
        GetCreatedJavaVMs = reinterpret_cast<GetCreatedJavaVMs_t>(
            dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    }

    if (GetCreatedJavaVMs == nullptr) {
        return nullptr;
    }

    JavaVM *vm = nullptr;
    jsize num_vms = 0;
    if (GetCreatedJavaVMs(&vm, 1, &num_vms) != JNI_OK || num_vms == 0 || vm == nullptr) {
        return nullptr;
    }

    JNIEnv *env = nullptr;
    jint result = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (result == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return nullptr;
        }
    } else if (result != JNI_OK) {
        return nullptr;
    }
    return env;
}

static void watcher_thread_fn() {
    dbg_log("watcher thread started");

    static bool lsplant_initialized = false;
    static bool hooks_installed = false;

    for (int i = 0; i < 300; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        JNIEnv *env = get_jni_env();
        if (env == nullptr) {
            if (i % 50 == 0) {
                dbg_log("get_jni_env() returned null (poll " + std::to_string(i) + ")");
            }
            continue;
        }

        if (!lsplant_initialized) {
            lsplant::InitInfo init_info{
                .inline_hooker = InlineHooker,
                .inline_unhooker = InlineUnhooker,
                .art_symbol_resolver = ArtSymbolResolver,
                .art_symbol_prefix_resolver = ArtSymbolPrefixResolver,
            };
            dbg_log("calling lsplant::Init...");
            lsplant_initialized = lsplant::Init(env, init_info);
            dbg_log(std::string("lsplant::Init result: ") + (lsplant_initialized ? "SUCCESS" : "FAILED"));
        }

        if (lsplant_initialized && !hooks_installed) {
            hook_all_dispatchers(env);
            hooks_installed = true;
        }

        if (hooks_installed) {
            dbg_log("watcher thread finishing after " + std::to_string(i) + " polls");
            return;
        }
    }
    dbg_log("watcher thread gave up after 300 polls (30s)");
}

__attribute__((constructor))
static void payload_init() {
    dbg_log("=== dump_dex_payload (C++/LSPlant) constructor called ===");
    std::thread(watcher_thread_fn).detach();
}
