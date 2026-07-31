use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info, trace};
use nix::{fcntl::OFlag, sys::stat::Mode};
use std::sync::atomic::{AtomicUsize, Ordering};
// use std::arch::asm;
use std::arch::naked_asm;
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};

struct MyModule {
    api: Api,
    env: JNIEnv<'static>,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        // DEBUG: ghi thẳng ra file ngay lập tức, KHÔNG qua log/android_logger,
        // để loại trừ khả năng android_logger bị lỗi/chưa init xong khiến
        // mọi log sau đó bị nuốt mất một cách âm thầm. Nếu Module::new()
        // thực sự được Zygisk gọi, file này PHẢI xuất hiện dù mọi thứ khác
        // có lỗi gì đi nữa (miễn là /data/local/tmp ghi được).
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/dump_dex_debug.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(
                    f,
                    "[{}] Module::new() called, pid={}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0),
                    std::process::id()
                )
            });

        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("dump_dex"),
        );

        // DEBUG thứ 2: ghi tiếp sau khi init_once để biết chính xác dòng
        // này có chạy tới hay không (phân biệt với crash TRONG init_once).
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/dump_dex_debug.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "android_logger::init_once() completed")
            });

        info!("=== dump_dex Module::new() via log crate ===");

        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };

        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/dump_dex_debug.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "JNIEnv::from_raw() completed, Module::new() returning")
            });

        Self { api, env }
    }
    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        // DEBUG: xác nhận pre_app_specialize được gọi, ghi luôn package
        // name thô (chưa qua bất kỳ xử lý gì) để biết có tới được đây không.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/dump_dex_debug.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "pre_app_specialize() ENTER, pid={}", std::process::id())
            });
        let mut inner = || -> anyhow::Result<()> {
            let package_name = self
                .env
                .get_string(unsafe {
                    (args.nice_name as *mut jni_sys::jstring as *mut ()
                        as *const jni::objects::JString<'_>)
                        .as_ref()
                        .unwrap()
                })?
                .to_string_lossy()
                .to_string();
            trace!("pre_app_specialize: package_name: {}", package_name);
            let module_dir = self
                .api
                .get_module_dir()
                .ok_or_else(|| anyhow::anyhow!("get_module_dir error"))?;
            let mut list_file = unsafe {
                File::from_raw_fd(nix::fcntl::openat(
                    Some(module_dir.as_raw_fd()),
                    "list.txt",
                    OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?)
            };
            let mut file_content = String::new();
            list_file.read_to_string(&mut file_content)?;

            let find: bool = file_content
                .split("\n")
                .any(|item| item.trim() == package_name);

            if !find {
                self.api
                    .set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
                return Ok(());
            }
            info!("dump {}", package_name);

            // Hook CẢ 2 symbol OpenCommon đã xác nhận tồn tại trên thiết bị
            // này (qua `nm -D libdexfile.so`): DexFileLoader::OpenCommon
            // (interface/wrapper phổ biến) và ArtDexFileLoader::OpenCommon
            // (implementation cụ thể). Một số app/packer có thể gọi thẳng
            // vào implementation, bỏ qua interface — hook cả 2 để không bỏ
            // sót trường hợp nào.
            let open_common = dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE")
                .ok_or_else(|| anyhow::anyhow!("resolve symbol error (DexFileLoader)"))?;
            info!("DexFileLoader::open_common addr: {:x}", open_common as usize);
            let hooked1 = unsafe {
                dobby_rs::hook(open_common, new_open_common_wrapper as Address)? as usize
            };
            OLD_OPEN_COMMON.store(hooked1, Ordering::SeqCst);

            let art_open_common = dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art16ArtDexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS_13DexFileLoader12VerifyResultE");
            match art_open_common {
                Some(addr) => {
                    info!("ArtDexFileLoader::open_common addr: {:x}", addr as usize);
                    let hooked2 = unsafe {
                        dobby_rs::hook(addr, new_art_open_common_wrapper as Address)? as usize
                    };
                    OLD_ART_OPEN_COMMON.store(hooked2, Ordering::SeqCst);
                }
                None => {
                    error!("resolve symbol error (ArtDexFileLoader), continuing with DexFileLoader hook only");
                }
            }

            // ================================================================
            // Hook RegisterNatives để bắt lúc libl5e5d2631.so đăng ký các hàm
            // native (F5e5d2631_00, I5e5d2631_00, ...) — vì nm -D xác nhận
            // các hàm này KHÔNG được export theo tên JNI chuẩn (Java_...),
            // nên chỉ có thể bắt được con trỏ hàm thật tại đúng thời điểm
            // JNI_OnLoad gọi RegisterNatives() để đăng ký chúng.
            //
            // RegisterNatives không phải 1 symbol export tĩnh theo tên C —
            // nó là 1 CON TRỎ HÀM bên trong struct JNINativeInterface mà
            // mỗi JNIEnv* trỏ tới (jni.h: (*env)->RegisterNatives(...)).
            // Ta lấy đúng con trỏ đó từ chính self.env đang có sẵn, rồi
            // patch nó bằng dobby_rs::hook — không cần resolve theo tên.
            // ================================================================
            unsafe {
                let raw_env = self.env.get_raw();
                // Theo chuẩn JNI (jni.h): JNIEnv là con trỏ tới con trỏ
                // tới function table (JNINativeInterface_). Tức là:
                //   raw_env: *mut JNIEnv  ==  *mut *const JNINativeInterface_
                // Deref 1 lần (*raw_env) để lấy con trỏ tới bảng hàm,
                // rồi deref thêm 1 lần nữa ((*raw_env) đã là con trỏ,
                // deref thêm để lấy giá trị struct) mới truy cập được
                // field RegisterNatives bên trong.
                let functions_ptr: *const jni_sys::JNINativeInterface_ = *raw_env;
                let register_natives_ptr = (*functions_ptr).RegisterNatives
                    .ok_or_else(|| anyhow::anyhow!("RegisterNatives function pointer is null"))?;

                info!("RegisterNatives original addr: {:x}", register_natives_ptr as usize);

                let hooked_addr = dobby_rs::hook(
                    register_natives_ptr as Address,
                    new_register_natives_wrapper as Address,
                )? as usize;
                OLD_REGISTER_NATIVES.store(hooked_addr, Ordering::SeqCst);

                info!("RegisterNatives hooked successfully");
            }

            Ok(())
        };
        if let Err(e) = inner() {
            error!("pre_app_specialize error: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _args: &AppSpecializeArgs) {}

    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}

    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);
// Cả 5 biến dưới đây dùng AtomicUsize theo khuyến nghị chính thức của
// Rust — tránh lint "creating a shared reference to mutable static"
// (hard error từ Rust 2024 edition). Đã xác nhận qua tài liệu Rust
// Reference: `sym` trong naked_asm! chấp nhận bất kỳ `static` item nào
// (kể cả AtomicUsize, vì nó có cùng bộ nhớ layout với usize nhờ
// #[repr(transparent)]) — KHÔNG bắt buộc phải là `static mut` như từng
// nhầm tưởng trước đó. AtomicUsize còn có lợi ích phụ: an toàn thực sự
// khi bị đọc/ghi đồng thời từ nhiều thread.
static OLD_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_ART_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_REGISTER_NATIVES: AtomicUsize = AtomicUsize::new(0);

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
        // options(noreturn)
    );
}

// Wrapper thứ 2, dành riêng cho ArtDexFileLoader::OpenCommon. Đã xác
// nhận qua ART source code thật (art_dex_file_loader.h) rằng đây CŨNG
// LÀ STATIC METHOD giống DexFileLoader::OpenCommon — không có `this`
// pointer ẩn, x0 vốn đã là `base` thật, không cần dịch chuyển thanh ghi.
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
        // options(noreturn)
    );
}

extern "C" fn new_open_common(base: usize, size: usize) {
    info!("find dex: base=0x{:x}, size=0x{:x}", base, size);

    let dex_data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    let package = match std::fs::read_to_string("/proc/self/cmdline") {
        Ok(cmdline) => cmdline,
        Err(e) => {
            error!("read cmdline error: {:?}", e);
            return;
        }
    };
    if package.is_empty() {
        error!("package name is empty");
        return;
    }
    let Some(package) = package.split('\0').next() else {
        error!("package name split by zero error: {}", package);
        return;
    };

    let dir = format!("/data/data/{}/dexes", package);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!("create dir error: {:?}", e);
        return;
    }

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
    let mut digest = crc.digest();
    digest.update(dex_data);

    let file_name = format!("/data/data/{}/dexes/{:08x}.dex", package, digest.finalize());
    if let Err(e) = std::fs::write(file_name, dex_data) {
        error!("write file error: {:?}", e);
    }
}

// =====================================================================
// Hook RegisterNatives — chữ ký C chuẩn, dùng extern "C" bình thường
// (không cần naked_asm vì đây không phải C++ method với ABI đặc biệt).
//
// jint RegisterNatives(JNIEnv *env, jclass clazz,
//                       const JNINativeMethod *methods, jint nMethods);
//
// struct JNINativeMethod { const char* name; const char* signature; void* fnPtr; };
// =====================================================================

#[repr(C)]
struct JNINativeMethodRaw {
    name: *const std::os::raw::c_char,
    signature: *const std::os::raw::c_char,
    fn_ptr: *mut std::os::raw::c_void,
}

static TARGET_METHOD_ADDR: AtomicUsize = AtomicUsize::new(0);
static OLD_F5E5D2631_00: AtomicUsize = AtomicUsize::new(0);

extern "system" fn new_register_natives_wrapper(
    env: *mut jni_sys::JNIEnv,
    clazz: jni_sys::jclass,
    methods: *const JNINativeMethodRaw,
    n_methods: jni_sys::jint,
) -> jni_sys::jint {
    unsafe {
        // Lấy tên class đang đăng ký native methods, để log cho biết
        // ngữ cảnh (class nào gọi RegisterNatives) — hữu ích để xác nhận
        // đúng đây là v5e5d2631/m5e5d2631 namespace trước khi đào sâu.
        let class_name = get_class_name_safe(env, clazz);
        info!(
            "RegisterNatives called: class={} n_methods={}",
            class_name, n_methods
        );

        for i in 0..n_methods as isize {
            let m = &*methods.offset(i);
            let name = std::ffi::CStr::from_ptr(m.name)
                .to_string_lossy()
                .to_string();
            let sig = std::ffi::CStr::from_ptr(m.signature)
                .to_string_lossy()
                .to_string();

            info!(
                "  native method: {} sig={} fnPtr=0x{:x}",
                name, sig, m.fn_ptr as usize
            );

            // Mục tiêu chính: F5e5d2631_00 — dispatcher chung của toàn bộ
            // method bị virtualize, xác nhận từ log crash trước đó nhận
            // (int methodId, Object[] args).
            if name == "F5e5d2631_00"
                && TARGET_METHOD_ADDR.load(Ordering::SeqCst) == 0
            {
                let fn_addr = m.fn_ptr as usize;
                TARGET_METHOD_ADDR.store(fn_addr, Ordering::SeqCst);
                info!(
                    "!!! FOUND F5e5d2631_00 dispatcher @ 0x{:x}, class={} !!!",
                    fn_addr, class_name
                );

                // Hook luôn ngay tại đây — dispatcher này nhận
                // (JNIEnv*, jclass, jint methodId, jobjectArray args)
                // theo chuẩn JNI static native method.
                match dobby_rs::hook(
                    fn_addr as Address,
                    new_f5e5d2631_00_wrapper as Address,
                ) {
                    Ok(old) => {
                        let old_addr = old as usize;
                        OLD_F5E5D2631_00.store(old_addr, Ordering::SeqCst);
                        info!("F5e5d2631_00 hooked successfully, trampoline=0x{:x}", old_addr);
                    }
                    Err(e) => {
                        error!("failed to hook F5e5d2631_00: {:?}", e);
                    }
                }
            }
        }
    }

    // Gọi hàm gốc để RegisterNatives vẫn hoạt động bình thường — KHÔNG
    // được chặn lời gọi thật, nếu không app sẽ crash vì thiếu native
    // method implementation.
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
    // env: *mut JNIEnv == *mut *const JNINativeInterface_ (chuẩn JNI).
    // Deref 1 lần để lấy con trỏ tới bảng hàm thật.
    let functions: *const jni_sys::JNINativeInterface_ = *env;
    let get_object_class = match (*functions).GetObjectClass {
        Some(f) => f,
        None => return "?".to_string(),
    };
    let class_of_class = get_object_class(env, clazz as jni_sys::jobject);

    // Gọi java.lang.Class#getName() qua JNI thủ công để lấy tên dạng
    // "a.b.C" (không dùng crate jni cấp cao để giảm rủi ro panic ở
    // native callback — 1 panic ở đây có thể crash toàn bộ app).
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

    let result = std::ffi::CStr::from_ptr(c_str).to_string_lossy().to_string();
    result
}

// =====================================================================
// Hook cho chính F5e5d2631_00 — dispatcher static native, chữ ký xác
// nhận từ log crash: void F5e5d2631_00(int methodId, Object[] args)
// Vì là STATIC method, tham số JNI thật sự nhận vào là:
//   (JNIEnv*, jclass, jint methodId, jobjectArray args)
// "Object[]" trong Java tương ứng jobjectArray ở tầng JNI, không phải
// jobject đơn — quan trọng để đọc đúng args nếu cần mở rộng sau này.
// =====================================================================
extern "system" fn new_f5e5d2631_00_wrapper(
    env: *mut jni_sys::JNIEnv,
    clazz: jni_sys::jclass,
    method_id: jni_sys::jint,
    args: jni_sys::jobjectArray,
) {
    info!(
        "F5e5d2631_00 CALLED: methodId={} (0x{:x}) args_ptr=0x{:x}",
        method_id, method_id, args as usize
    );

    // Log ra file riêng để dễ đối chiếu theo thời gian, vì logcat có thể
    // bị rotate/mất nếu app chạy lâu. Đồng thời log luôn độ dài mảng
    // args (nếu đọc được) để biết mỗi methodId truyền vào bao nhiêu
    // tham số — hữu ích khi đối chiếu ngược với DEX đã dump được.
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
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                {
                    use std::io::Write;
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    let _ = writeln!(
                        f,
                        "[{}] methodId={} args_ptr=0x{:x} args_len={}",
                        ts, method_id, args as usize, array_len
                    );
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
