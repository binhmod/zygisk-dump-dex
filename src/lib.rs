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

// =========================================================================
// CUSTOM SYMBOL RESOLVER
// -----------------------------------------------------------------------
// LÝ DO CẦN THAY THẾ dobby_rs::resolve_symbol(): tombstone log xác nhận
// dobby's symbol resolver tự động quét TOÀN BỘ module đã load trong tiến
// trình, kể cả memfd của chính payload này ("/memfd:zygisk-payload
// (deleted)") — vì memfd đã bị unlink khỏi filesystem (đặc tính kỹ thuật
// injection của Zygisk-Loader), việc dobby cố file_mmap() nó thất bại,
// và có vẻ dẫn tới SEGV ngay sau đó (crash xảy ra đúng lúc đang resolve).
//
// Giải pháp: tự viết resolver tối giản, CHỈ xử lý đúng 1 module cần
// (libart.so) — đọc base address thật từ /proc/self/maps (không quét
// toàn bộ), rồi đọc offset symbol từ chính file .so đó trên đĩa qua ELF
// dynamic symbol table (.dynsym + .dynstr), không đụng tới memfd nào cả.
// =========================================================================
mod resolver {
    use std::fs;
    use std::io::Read;

    /// Tìm base address thật (nơi bắt đầu vùng nhớ executable) của 1 module
    /// theo tên, bằng cách đọc /proc/self/maps. Trả về (base_address, đường
    /// dẫn file thật trên đĩa) để dùng tiếp cho việc đọc ELF.
    pub fn find_module_base(module_name: &str) -> Option<(usize, String)> {
        let maps = fs::read_to_string("/proc/self/maps").ok()?;

        for line in maps.lines() {
            if !line.contains(module_name) {
                continue;
            }
            // Format dòng /proc/self/maps:
            // 7b0f...000-7b0f...000 r-xp 00000000 fd:03 1234  /path/to/lib.so
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let addr_range = parts[0];
            let path = parts[5];

            // Chỉ lấy dòng đầu tiên khớp — thường đây là base address thật
            // (offset trong file = 0, vùng đầu tiên được map).
            let offset_in_file = parts[2];
            if offset_in_file != "00000000" {
                continue;
            }

            let start_str = addr_range.split('-').next()?;
            let base = usize::from_str_radix(start_str, 16).ok()?;

            return Some((base, path.to_string()));
        }
        None
    }

    /// Đọc ELF dynamic symbol table (.dynsym + .dynstr) từ file thật trên
    /// đĩa để tìm OFFSET (không phải địa chỉ tuyệt đối) của 1 symbol theo
    /// tên chính xác. Đây là parser ELF64 tối giản, chỉ đủ dùng cho mục
    /// đích này — không cần crate ngoài (goblin/object) để giảm phụ thuộc.
    pub fn find_symbol_offset(file_path: &str, symbol_name: &str) -> Option<usize> {
        let mut file = fs::File::open(file_path).ok()?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).ok()?;

        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return None;
        }
        let is_64bit = data[4] == 2;
        if !is_64bit {
            return None; // chỉ hỗ trợ ELF64 (arm64-v8a luôn là 64-bit)
        }

        // ELF64 header offsets (theo chuẩn ELF spec):
        // e_shoff (section header offset): byte 0x28, 8 bytes
        // e_shentsize: byte 0x3A, 2 bytes
        // e_shnum: byte 0x3C, 2 bytes
        // e_shstrndx: byte 0x3E, 2 bytes
        let e_shoff = read_u64(&data, 0x28)?;
        let e_shentsize = read_u16(&data, 0x3A)? as usize;
        let e_shnum = read_u16(&data, 0x3C)? as usize;
        let e_shstrndx = read_u16(&data, 0x3E)? as usize;

        if e_shoff == 0 || e_shnum == 0 {
            return None;
        }

        // Đọc section header string table (để biết tên từng section).
        let shstrtab_hdr_off = e_shoff as usize + e_shstrndx * e_shentsize;
        let shstrtab_offset = read_u64(&data, shstrtab_hdr_off + 0x18)? as usize;

        let mut dynsym_offset = 0usize;
        let mut dynsym_size = 0usize;
        let mut dynsym_entsize = 0usize;
        let mut dynstr_offset = 0usize;

        for i in 0..e_shnum {
            let sh_off = e_shoff as usize + i * e_shentsize;
            let name_idx = read_u32(&data, sh_off)? as usize;
            let sh_type = read_u32(&data, sh_off + 4)?;
            let sh_offset = read_u64(&data, sh_off + 0x18)? as usize;
            let sh_size = read_u64(&data, sh_off + 0x20)? as usize;
            let sh_entsize = read_u64(&data, sh_off + 0x38)? as usize;

            let name = read_cstr(&data, shstrtab_offset + name_idx)?;

            // SHT_DYNSYM = 11, SHT_STRTAB = 3 (nhưng cần đúng .dynstr,
            // không phải .strtab thường — phân biệt qua tên section).
            if sh_type == 11 && name == ".dynsym" {
                dynsym_offset = sh_offset;
                dynsym_size = sh_size;
                dynsym_entsize = sh_entsize;
            } else if name == ".dynstr" {
                dynstr_offset = sh_offset;
            }
        }

        if dynsym_offset == 0 || dynsym_entsize == 0 || dynstr_offset == 0 {
            return None;
        }

        let num_symbols = dynsym_size / dynsym_entsize;

        // Elf64_Sym layout: st_name(4) st_info(1) st_other(1) st_shndx(2)
        //                    st_value(8) st_size(8)  = 24 bytes total
        for i in 0..num_symbols {
            let sym_off = dynsym_offset + i * dynsym_entsize;
            let st_name_idx = read_u32(&data, sym_off)? as usize;
            let st_value = read_u64(&data, sym_off + 8)? as usize;

            if st_value == 0 {
                continue; // symbol undefined/không có địa chỉ, bỏ qua
            }

            let name = read_cstr(&data, dynstr_offset + st_name_idx)?;
            if name == symbol_name {
                return Some(st_value);
            }
        }

        None
    }

    /// Kết hợp 2 hàm trên: tìm địa chỉ TUYỆT ĐỐI trong bộ nhớ của 1 symbol
    /// trong 1 module đang chạy, không dùng dobby's resolver.
    pub fn resolve_symbol_safe(module_name: &str, symbol_name: &str) -> Option<usize> {
        let (base, path) = find_module_base(module_name)?;
        let offset = find_symbol_offset(&path, symbol_name)?;
        Some(base + offset)
    }

    fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
        data.get(offset..offset + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
        data.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
        data.get(offset..offset + 8).map(|b| {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
        let slice = data.get(offset..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        String::from_utf8(slice[..end].to_vec()).ok()
    }
}

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

    // QUAN TRỌNG — SỬA LẦN 2: log tombstone trước cho thấy crash xảy ra
    // ngay trong watcher thread (#06 pc ... __pthread_start), rất có thể
    // do RACE CONDITION — main thread của app đang THỰC THI CHÍNH
    // RegisterNatives cùng lúc watcher thread cố GHI TRAMPOLINE đè lên
    // đúng vùng code đó (dobby_rs::hook làm inline patch, không an toàn
    // nếu có thread khác đang chạy ngay tại địa chỉ bị patch).
    //
    // Cách sửa: hook RegisterNatives NGAY TẠI ĐÂY, đồng bộ, trong chính
    // luồng thực thi của #[ctor] — đây là thời điểm sớm nhất có thể,
    // trước khi bất kỳ code Java nào của app kịp chạy (vì #[ctor] chạy
    // ngay lúc dlopen(), trước cả khi control quay lại cho code gọi
    // dlopen). Giảm mạnh cửa sổ race condition so với đợi thread riêng.
    dbg_log("attempting SYNCHRONOUS hook of RegisterNatives right in ctor (before spawning watcher thread)");
    if try_hook_register_natives_direct() {
        JNI_ONLOAD_HOOKED.store(1, Ordering::SeqCst);
        dbg_log("RegisterNatives hooked SYNCHRONOUSLY in ctor — success");
    } else {
        dbg_log("libart.so chưa sẵn sàng lúc ctor chạy, sẽ retry qua watcher thread");
    }

    // OpenCommon vẫn cần chờ (libdexfile.so có thể chưa load lúc ctor
    // chạy quá sớm), giữ nguyên watcher thread cho phần này.
    std::thread::spawn(|| {
        dbg_log("watcher thread started, polling for libdexfile.so + retry RegisterNatives if needed");

        for i in 0..300 {
            std::thread::sleep(std::time::Duration::from_millis(100));

            if OPEN_COMMON_HOOKED.load(Ordering::SeqCst) == 0 {
                dbg_log(&format!("poll #{}: trying try_hook_open_common()", i));
                if try_hook_open_common() {
                    OPEN_COMMON_HOOKED.store(1, Ordering::SeqCst);
                    dbg_log("OpenCommon hooks installed successfully");
                }
            }

            // Retry RegisterNatives CHỈ NẾU chưa hook được đồng bộ ở trên
            // (trường hợp libart.so chưa sẵn sàng lúc ctor chạy quá sớm).
            // Đây vẫn có rủi ro race condition như bản cũ, nhưng chỉ là
            // fallback hiếm khi cần tới.
            if JNI_ONLOAD_HOOKED.load(Ordering::SeqCst) == 0 {
                dbg_log(&format!("poll #{}: retry try_hook_register_natives_direct()", i));
                if try_hook_register_natives_direct() {
                    JNI_ONLOAD_HOOKED.store(1, Ordering::SeqCst);
                    dbg_log("RegisterNatives hooked via watcher thread retry — success");
                }
            }

            if OPEN_COMMON_HOOKED.load(Ordering::SeqCst) == 1
                && JNI_ONLOAD_HOOKED.load(Ordering::SeqCst) == 1
            {
                dbg_log(&format!("all hooks installed after {} polls, watcher exiting", i));
                return;
            }
        }
        dbg_log("watcher thread gave up after 300 polls (30s), some hooks may be missing");
    });
}

static OPEN_COMMON_HOOKED: AtomicUsize = AtomicUsize::new(0);
static JNI_ONLOAD_HOOKED: AtomicUsize = AtomicUsize::new(0);
static OLD_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_ART_OPEN_COMMON: AtomicUsize = AtomicUsize::new(0);
static OLD_REGISTER_NATIVES: AtomicUsize = AtomicUsize::new(0);
static TARGET_METHOD_ADDR: AtomicUsize = AtomicUsize::new(0);
static OLD_F5E5D2631_00: AtomicUsize = AtomicUsize::new(0);

// =========================================================================
// Hook OpenCommon (giữ nguyên logic đã sửa đúng ABI — cả 2 hàm đều là
// STATIC method, x0 = base thật, không cần dịch thanh ghi).
// =========================================================================
fn try_hook_open_common() -> bool {
    let open_common_addr = match resolver::resolve_symbol_safe(
        "libdexfile.so",
        "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE",
    ) {
        Some(addr) => addr,
        None => return false, // libdexfile.so chưa load hoặc symbol không tìm thấy, thử lại ở vòng poll sau
    };

    dbg_log(&format!("DexFileLoader::OpenCommon addr: {:x}", open_common_addr));
    match unsafe { dobby_rs::hook(open_common_addr as Address, new_open_common_wrapper as Address) } {
        Ok(old) => OLD_OPEN_COMMON.store(old as usize, Ordering::SeqCst),
        Err(e) => {
            dbg_log(&format!("hook DexFileLoader::OpenCommon failed: {:?}", e));
            return false;
        }
    }

    if let Some(addr) = resolver::resolve_symbol_safe(
        "libdexfile.so",
        "_ZN3art16ArtDexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS_13DexFileLoader12VerifyResultE",
    ) {
        dbg_log(&format!("ArtDexFileLoader::OpenCommon addr: {:x}", addr));
        match unsafe { dobby_rs::hook(addr as Address, new_art_open_common_wrapper as Address) } {
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
// Hook TRỰC TIẾP art::JNI::RegisterNatives trong libart.so.
//
// LÝ DO ĐỔI CHIẾN LƯỢC: cách cũ (hook JNI_OnLoad của libl5e5d2631.so rồi
// mới lấy JNIEnv* để hook RegisterNatives) có lỗ hổng logic nghiêm trọng
// — nếu #[ctor] của payload chạy SAU thời điểm app đã tự gọi
// System.loadLibrary() xong (rất có thể xảy ra, vì #[ctor] phụ thuộc lúc
// Zygisk-Loader inject, không đảm bảo sớm hơn app tự load lib đích), thì
// JNI_OnLoad thật đã chạy và kết thúc từ trước — hook đặt vào lúc đó sẽ
// KHÔNG BAO GIỜ được gọi lại, khiến toàn bộ watcher poll vô ích.
//
// Cách mới: hook thẳng symbol implementation thật của RegisterNatives
// bên trong libart.so — _ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclass
// PK15JNINativeMethodi (art::JNI::RegisterNatives). Đây là hàm DUY NHẤT
// mọi RegisterNatives() call (từ BẤT KỲ lib nào, BẤT KỲ lúc nào) đều đi
// qua — libart.so luôn có sẵn ngay từ khi ART runtime khởi động, không
// phụ thuộc app cụ thể đã gọi gì hay chưa tại thời điểm hook được đặt.
// =========================================================================
fn try_hook_register_natives_direct() -> bool {
    let addr = match resolver::resolve_symbol_safe(
        "libart.so",
        "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi",
    ) {
        Some(a) => a,
        None => {
            dbg_log("resolve_symbol_safe art::JNI::RegisterNatives in libart.so -> None (chưa load hoặc symbol khác tên trên Android version này)");
            return false;
        }
    };

    dbg_log(&format!("art::JNI::RegisterNatives addr: {:x}", addr));
    match unsafe { dobby_rs::hook(addr as Address, new_register_natives_wrapper as Address) } {
        Ok(old) => {
            OLD_REGISTER_NATIVES.store(old as usize, Ordering::SeqCst);
            dbg_log("art::JNI::RegisterNatives hooked successfully");
            true
        }
        Err(e) => {
            dbg_log(&format!("hook art::JNI::RegisterNatives failed: {:?}", e));
            false
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
