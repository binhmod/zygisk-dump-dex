// =========================================================================
// dump_dex_payload.rs
// -----------------------------------------------------------------------
// Payload theo pattern của Zygisk-Loader (github.com/HanSoBored/Zygisk-Loader):
// KHÔNG dùng register_zygisk_module!/Module trait của crate zygisk_rs (vốn
// yêu cầu framework Zygisk chuẩn tự gọi vào entry point riêng — điều mà
// Zygisk-Loader không làm, nó chỉ đơn thuần dlopen() file .so như 1 thư
// viện thường). Thay vào đó dùng #[ctor] — hàm này tự chạy NGAY KHI
// dlopen() thành công, không cần framework nào gọi vào.
//
// Vì không còn Module::pre_app_specialize (nơi trước đây lấy JNIEnv qua
// Zygisk API self.env), cần lấy JNIEnv bằng cách khác: hook thẳng
// JNI_OnLoad của chính libl5e5d2631.so — đây là hàm chắc chắn sẽ được
// gọi với đúng JNIEnv* của tiến trình app, ngay sau khi lib đó tự load.
//
// Cargo.toml cần:
//   [lib]
//   crate-type = ["cdylib"]
//   [dependencies]
//   ctor = "0.2"
//   android_logger = "0.13"
//   log = "0.4"
//   dobby-rs = "..."   (giữ nguyên dependency cũ)
//   jni-sys = "..."    (giữ nguyên dependency cũ)
//   anyhow = "..."
// =========================================================================

use ctor::ctor;
use dobby_rs::Address;
use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::arch::naked_asm;

fn dbg_log(msg: &str) {
    // Ghi thẳng ra file, KHÔNG qua log/android_logger — dùng làm lớp bảo
    // hiểm cuối cùng để biết chắc code có chạy tới đâu, kể cả khi
    // android_logger có vấn đề (giữ nguyên chiến lược debug đã dùng).
    if let Ok(pkg) = std::fs::read_to_string("/proc/self/cmdline") {
        let pkg = pkg.split('\0').next().unwrap_or("unknown").to_string();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/dump_dex_debug.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "[{}] pid={} pkg={} {}", ts, std::process::id(), pkg, msg)
            });
    }
}

// =========================================================================
// ENTRY POINT — chạy tự động ngay khi Zygisk-Loader dlopen() file này.
// =========================================================================
#[ctor]
fn init() {
    dbg_log("ctor init() called");

    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("dump_dex"),
    );
    info!("=== dump_dex payload init (via #[ctor]) ===");
    dbg_log("android_logger init_once completed");

    // Vì #[ctor] chạy RẤT SỚM (ngay khi thư viện được nạp), có thể trước
    // cả khi libl5e5d2631.so đã load xong (nếu Zygisk-Loader inject sớm
    // hơn lúc app tự System.load() thư viện đó). Cần đợi + poll cho tới
    // khi libl5e5d2631.so xuất hiện trong tiến trình rồi mới hook.
    std::thread::spawn(|| {
        dbg_log("watcher thread started, polling for libl5e5d2631.so + libdexfile.so");

        for i in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(100));

            // --- Hook OpenCommon (libdexfile.so) — chỉ làm 1 lần ---
            if OPEN_COMMON_HOOKED.load(Ordering::SeqCst) == 0 {
                if try_hook_open_common() {
                    OPEN_COMMON_HOOKED.store(1, Ordering::SeqCst);
                    dbg_log("OpenCommon hooks installed successfully");
                }
            }

            // --- Hook JNI_OnLoad của libl5e5d2631.so — chỉ làm 1 lần ---
            if JNI_ONLOAD_HOOKED.load(Ordering::SeqCst) == 0 {
                if try_hook_target_jni_onload() {
                    JNI_ONLOAD_HOOKED.store(1, Ordering::SeqCst);
                    dbg_log("target JNI_OnLoad hook installed successfully");
                }
            }

            if OPEN_COMMON_HOOKED.load(Ordering::SeqCst) == 1
                && JNI_ONLOAD_HOOKED.load(Ordering::SeqCst) == 1
            {
                dbg_log(&format!("all hooks installed after {} polls, watcher exiting", i));
                return;
            }
        }
        dbg_log("watcher thread gave up after 100 polls (10s), some hooks may be missing");
    });
}

static OPEN_COMMON_HOOKED: AtomicUsize = AtomicUsize::new(0);
static JNI_ONLOAD_HOOKED: AtomicUsize = AtomicUsize::new(0);
static OLD_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_ART_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_TARGET_JNI_ONLOAD: AtomicUsize = AtomicUsize::new(0);
static OLD_REGISTER_NATIVES: AtomicUsize = AtomicUsize::new(0);
static TARGET_METHOD_ADDR: AtomicUsize = AtomicUsize::new(0);
static OLD_F5E5D2631_00: AtomicUsize = AtomicUsize::new(0);

// =========================================================================
// Hook OpenCommon (giữ nguyên logic đã sửa đúng ABI — cả 2 hàm đều là
// STATIC method, x0 = base thật, không cần dịch thanh ghi).
// =========================================================================
fn try_hook_open_common() -> bool {
    let open_common = match dobby_rs::resolve_symbol(
        "libdexfile.so",
        "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE",
    ) {
        Some(addr) => addr,
        None => return false, // libdexfile.so chưa load, thử lại ở vòng poll sau
    };

    dbg_log(&format!("DexFileLoader::OpenCommon addr: {:x}", open_common as usize));
    match unsafe { dobby_rs::hook(open_common, new_open_common_wrapper as Address) } {
        Ok(old) => OLD_OPEN_COMMON.store(old as usize, Ordering::SeqCst),
        Err(e) => {
            dbg_log(&format!("hook DexFileLoader::OpenCommon failed: {:?}", e));
            return false;
        }
    }

    if let Some(addr) = dobby_rs::resolve_symbol(
        "libdexfile.so",
        "_ZN3art16ArtDexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS_13DexFileLoader12VerifyResultE",
    ) {
        dbg_log(&format!("ArtDexFileLoader::OpenCommon addr: {:x}", addr as usize));
        match unsafe { dobby_rs::hook(addr, new_art_open_common_wrapper as Address) } {
            Ok(old) => OLD_ART_OPEN_COMMON.store(old as usize, Ordering::SeqCst),
            Err(e) => dbg_log(&format!("hook ArtDexFileLoader::OpenCommon failed: {:?}", e)),
        }
    }

    true
}

#[unsafe(naked)]
pub extern "C" fn new_open_common_wrapper() {
    naked_asm!(
        r#"
        sub sp, sp, 0x280
        stp x29, x30, [sp, #0]
        stp x0, x1, [sp, #0x10]
        stp x2, x3, [sp, #0x20]
        stp x4, x5, [sp, #0x30]
        stp x6, x7, [sp, #0x40]
        stp x8, x9, [sp, #0x50]

        bl {new_open_common}

        ldp x29, x30, [sp, #0]
        ldp x0, x1, [sp, #0x10]
        ldp x2, x3, [sp, #0x20]
        ldp x4, x5, [sp, #0x30]
        ldp x6, x7, [sp, #0x40]
        ldp x8, x9, [sp, #0x50]
        add sp, sp, 0x280
        adrp x16, {old_open_common}
        ldr x16, [x16, #:lo12:{old_open_common}]
        br x16"#,
        new_open_common = sym new_open_common,
        old_open_common = sym OLD_OPEN_COMMON,
    );
}

#[unsafe(naked)]
pub extern "C" fn new_art_open_common_wrapper() {
    naked_asm!(
        r#"
        sub sp, sp, 0x280
        stp x29, x30, [sp, #0]
        stp x0, x1, [sp, #0x10]
        stp x2, x3, [sp, #0x20]
        stp x4, x5, [sp, #0x30]
        stp x6, x7, [sp, #0x40]
        stp x8, x9, [sp, #0x50]

        bl {new_open_common}

        ldp x29, x30, [sp, #0]
        ldp x0, x1, [sp, #0x10]
        ldp x2, x3, [sp, #0x20]
        ldp x4, x5, [sp, #0x30]
        ldp x6, x7, [sp, #0x40]
        ldp x8, x9, [sp, #0x50]
        add sp, sp, 0x280
        adrp x16, {old_art_open_common}
        ldr x16, [x16, #:lo12:{old_art_open_common}]
        br x16"#,
        new_open_common = sym new_open_common,
        old_art_open_common = sym OLD_ART_OPEN_COMMON,
    );
}

extern "C" fn new_open_common(base: usize, size: usize) {
    dbg_log(&format!("find dex: base=0x{:x}, size=0x{:x}", base, size));
    info!("find dex: base=0x{:x}, size=0x{:x}", base, size);

    // Sanity check trước khi đọc — tránh crash nếu size bất thường do
    // đọc nhầm tham số (phòng hờ, dù đã sửa đúng ABI).
    if size == 0 || size > 200 * 1024 * 1024 {
        dbg_log(&format!("suspicious size {}, skipping dump", size));
        return;
    }

    let dex_data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };

    // Xác nhận magic DEX trước khi ghi, tránh dump rác nếu vẫn còn lệch
    // tham số ở đâu đó chưa phát hiện ra.
    if dex_data.len() < 8 || &dex_data[0..3] != b"dex" {
        dbg_log("data does not start with DEX magic, skipping (param offset may still be wrong)");
        return;
    }

    let package = match std::fs::read_to_string("/proc/self/cmdline") {
        Ok(c) => c.split('\0').next().unwrap_or("unknown").to_string(),
        Err(_) => return,
    };

    let dir = format!("/data/data/{}/dexes", package);
    if std::fs::create_dir_all(&dir).is_err() {
        dbg_log(&format!("create dir {} failed", dir));
        return;
    }

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
    let mut digest = crc.digest();
    digest.update(dex_data);
    let file_name = format!("{}/{:08x}.dex", dir, digest.finalize());

    match std::fs::write(&file_name, dex_data) {
        Ok(_) => dbg_log(&format!("saved {} ({} bytes)", file_name, size)),
        Err(e) => dbg_log(&format!("write {} failed: {:?}", file_name, e)),
    }
}

// =========================================================================
// Hook JNI_OnLoad của libl5e5d2631.so — điểm lấy JNIEnv* để sau đó hook
// RegisterNatives. Đây là điểm thay thế cho self.env vốn chỉ có sẵn qua
// Zygisk API (giờ không dùng nữa).
// =========================================================================
fn try_hook_target_jni_onload() -> bool {
    let addr = match dobby_rs::resolve_symbol("libl5e5d2631.so", "JNI_OnLoad") {
        Some(a) => a,
        None => return false, // lib chưa load, thử lại vòng poll sau
    };

    dbg_log(&format!("libl5e5d2631.so JNI_OnLoad addr: {:x}", addr as usize));
    match unsafe { dobby_rs::hook(addr, new_target_jni_onload_wrapper as Address) } {
        Ok(old) => {
            OLD_TARGET_JNI_ONLOAD.store(old as usize, Ordering::SeqCst);
            true
        }
        Err(e) => {
            dbg_log(&format!("hook JNI_OnLoad failed: {:?}", e));
            false
        }
    }
}

// JNI_OnLoad chữ ký chuẩn: jint JNI_OnLoad(JavaVM* vm, void* reserved)
// Đây LÀ hàm C thường (extern "C"/"system", không phải C++ method), nên
// KHÔNG cần naked_asm — dùng extern "system" bình thường là đủ.
extern "system" fn new_target_jni_onload_wrapper(
    vm: *mut jni_sys::JavaVM,
    reserved: *mut std::os::raw::c_void,
) -> jni_sys::jint {
    dbg_log("target libl5e5d2631.so JNI_OnLoad CALLED — hooking RegisterNatives now");

    // Lấy JNIEnv* từ JavaVM bằng GetEnv — cách chuẩn để có JNIEnv* hợp lệ
    // tại đúng thread hiện tại.
    unsafe {
        let vm_functions = *vm;
        if let Some(get_env) = (*vm_functions).GetEnv {
            let mut env_ptr: *mut std::os::raw::c_void = std::ptr::null_mut();
            let jni_version = 0x00010006; // JNI_VERSION_1_6
            let result = get_env(vm, &mut env_ptr, jni_version);

            if result == 0 && !env_ptr.is_null() {
                let env = env_ptr as *mut jni_sys::JNIEnv;
                hook_register_natives(env);
            } else {
                dbg_log(&format!("GetEnv failed, result={}", result));
            }
        } else {
            dbg_log("JavaVM.GetEnv function pointer is null");
        }
    }

    // Gọi hàm gốc để JNI_OnLoad thật vẫn chạy bình thường — bắt buộc,
    // nếu không app sẽ crash vì lib tưởng mình chưa init xong.
    unsafe {
        let orig: extern "system" fn(
            *mut jni_sys::JavaVM,
            *mut std::os::raw::c_void,
        ) -> jni_sys::jint = std::mem::transmute(OLD_TARGET_JNI_ONLOAD.load(Ordering::SeqCst));
        orig(vm, reserved)
    }
}

unsafe fn hook_register_natives(env: *mut jni_sys::JNIEnv) {
    let functions_ptr: *const jni_sys::JNINativeInterface_ = *env;
    let register_natives_ptr = match (*functions_ptr).RegisterNatives {
        Some(f) => f,
        None => {
            dbg_log("RegisterNatives function pointer is null");
            return;
        }
    };

    dbg_log(&format!("RegisterNatives original addr: {:x}", register_natives_ptr as usize));

    match dobby_rs::hook(
        register_natives_ptr as Address,
        new_register_natives_wrapper as Address,
    ) {
        Ok(old) => {
            OLD_REGISTER_NATIVES.store(old as usize, Ordering::SeqCst);
            dbg_log("RegisterNatives hooked successfully");
        }
        Err(e) => {
            dbg_log(&format!("hook RegisterNatives failed: {:?}", e));
        }
    }
}

#[repr(C)]
struct JNINativeMethodRaw {
    name: *const std::os::raw::c_char,
    signature: *const std::os::raw::c_char,
    fn_ptr: *mut std::os::raw::c_void,
}

extern "system" fn new_register_natives_wrapper(
    env: *mut jni_sys::JNIEnv,
    clazz: jni_sys::jclass,
    methods: *const JNINativeMethodRaw,
    n_methods: jni_sys::jint,
) -> jni_sys::jint {
    unsafe {
        let class_name = get_class_name_safe(env, clazz);
        dbg_log(&format!(
            "RegisterNatives called: class={} n_methods={}",
            class_name, n_methods
        ));

        for i in 0..n_methods as isize {
            let m = &*methods.offset(i);
            let name = std::ffi::CStr::from_ptr(m.name).to_string_lossy().to_string();
            let sig = std::ffi::CStr::from_ptr(m.signature).to_string_lossy().to_string();

            dbg_log(&format!(
                "  native method: {} sig={} fnPtr=0x{:x}",
                name, sig, m.fn_ptr as usize
            ));

            if name == "F5e5d2631_00" && TARGET_METHOD_ADDR.load(Ordering::SeqCst) == 0 {
                let fn_addr = m.fn_ptr as usize;
                TARGET_METHOD_ADDR.store(fn_addr, Ordering::SeqCst);
                dbg_log(&format!(
                    "!!! FOUND F5e5d2631_00 dispatcher @ 0x{:x}, class={} !!!",
                    fn_addr, class_name
                ));

                match dobby_rs::hook(fn_addr as Address, new_f5e5d2631_00_wrapper as Address) {
                    Ok(old) => {
                        OLD_F5E5D2631_00.store(old as usize, Ordering::SeqCst);
                        dbg_log("F5e5d2631_00 hooked successfully");
                    }
                    Err(e) => dbg_log(&format!("failed to hook F5e5d2631_00: {:?}", e)),
                }
            }
        }
    }

    unsafe {
        let orig: extern "system" fn(
            *mut jni_sys::JNIEnv,
            jni_sys::jclass,
            *const JNINativeMethodRaw,
            jni_sys::jint,
        ) -> jni_sys::jint = std::mem::transmute(OLD_REGISTER_NATIVES.load(Ordering::SeqCst));
        orig(env, clazz, methods, n_methods)
    }
}

unsafe fn get_class_name_safe(env: *mut jni_sys::JNIEnv, clazz: jni_sys::jclass) -> String {
    let functions: *const jni_sys::JNINativeInterface_ = *env;
    let get_object_class = match (*functions).GetObjectClass {
        Some(f) => f,
        None => return "?".to_string(),
    };
    let class_of_class = get_object_class(env, clazz as jni_sys::jobject);

    let find_class = match (*functions).FindClass {
        Some(f) => f,
        None => return "?".to_string(),
    };
    let get_method_id = match (*functions).GetMethodID {
        Some(f) => f,
        None => return "?".to_string(),
    };
    let call_object_method = match (*functions).CallObjectMethodA {
        Some(f) => f,
        None => return "?".to_string(),
    };
    let get_string_utf_chars = match (*functions).GetStringUTFChars {
        Some(f) => f,
        None => return "?".to_string(),
    };

    let class_class_name = std::ffi::CString::new("java/lang/Class").unwrap();
    let class_class = find_class(env, class_class_name.as_ptr());
    if class_class.is_null() {
        return "?".to_string();
    }

    let method_name = std::ffi::CString::new("getName").unwrap();
    let sig = std::ffi::CString::new("()Ljava/lang/String;").unwrap();
    let get_name_method = get_method_id(env, class_class, method_name.as_ptr(), sig.as_ptr());
    if get_name_method.is_null() {
        return "?".to_string();
    }

    let name_jstring = call_object_method(env, class_of_class, get_name_method, std::ptr::null());
    if name_jstring.is_null() {
        return "?".to_string();
    }

    let mut is_copy: jni_sys::jboolean = 0;
    let c_str = get_string_utf_chars(env, name_jstring as jni_sys::jstring, &mut is_copy);
    if c_str.is_null() {
        return "?".to_string();
    }

    std::ffi::CStr::from_ptr(c_str).to_string_lossy().to_string()
}

extern "system" fn new_f5e5d2631_00_wrapper(
    env: *mut jni_sys::JNIEnv,
    clazz: jni_sys::jclass,
    method_id: jni_sys::jint,
    args: jni_sys::jobjectArray,
) {
    dbg_log(&format!(
        "F5e5d2631_00 CALLED: methodId={} args_ptr=0x{:x}",
        method_id, args as usize
    ));

    unsafe {
        let array_len = if !args.is_null() {
            let functions: *const jni_sys::JNINativeInterface_ = *env;
            match (*functions).GetArrayLength {
                Some(get_len) => get_len(env, args as jni_sys::jarray),
                None => -1,
            }
        } else {
            -1
        };

        if let Ok(cmdline) = std::fs::read_to_string("/proc/self/cmdline") {
            if let Some(package) = cmdline.split('\0').next() {
                let dir = format!("/data/data/{}/dexes", package);
                let _ = std::fs::create_dir_all(&dir);
                let log_path = format!("{}/method_calls.log", dir);
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                    use std::io::Write;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    let _ = writeln!(f, "[{}] methodId={} args_len={}", ts, method_id, array_len);
                }
            }
        }
    }

    unsafe {
        let orig: extern "system" fn(
            *mut jni_sys::JNIEnv,
            jni_sys::jclass,
            jni_sys::jint,
            jni_sys::jobjectArray,
        ) = std::mem::transmute(OLD_F5E5D2631_00.load(Ordering::SeqCst));
        orig(env, clazz, method_id, args)
    }
}
