package dump.dex.hook;

/**
 * HookStub — 10 method callback tĩnh, mỗi cái tương ứng 1 dispatcher
 * F5e5d2631_00 đến F5e5d2631_09 của VirBox (xác nhận cấu trúc từ
 * m5e5d2631.smali, class 779828c7.dex đã dump trước đó).
 *
 * LSPlant yêu cầu callback_method có chữ ký CHÍNH XÁC:
 *   public Object callback_method(Object[] args)
 * (static hay không đều được, ở đây dùng static cho đơn giản).
 *
 * Vì tất cả 10 dispatcher gốc đều là static native (int, Object[]) với
 * return type khác nhau (void/boolean/byte/.../Object), nhưng LSPlant
 * "chuẩn hoá" mọi callback về cùng 1 chữ ký (Object[])->Object bất kể
 * return type thật của target_method — LSPlant tự lo việc box/unbox giá
 * trị trả về đúng kiểu thật khi gọi lại vào target thật, ta chỉ cần trả
 * về đúng kiểu Object tương ứng (hoặc null cho void).
 *
 * Mỗi callback gọi ngược vào native qua onDispatcherCalled() để: (1) log
 * methodId, (2) log toàn bộ args, (3) LẤY VÀ GỌI backup method (đã lưu ở
 * native side lúc Hook() thành công) để giữ đúng hành vi gốc của app.
 */
public class HookStub {

    // Native method: log context + gọi backup method tương ứng dispatcherIdx,
    // trả về đúng giá trị mà backup method trả (đã box sẵn thành Object ở
    // native side nếu cần, việc unbox về đúng kiểu do LSPlant tự xử lý).
    private static native Object onDispatcherCalled(int dispatcherIdx, Object[] args);

    public static Object callback_00(Object[] args) {
        return onDispatcherCalled(0, args);
    }

    public static Object callback_01(Object[] args) {
        return onDispatcherCalled(1, args);
    }

    public static Object callback_02(Object[] args) {
        return onDispatcherCalled(2, args);
    }

    public static Object callback_03(Object[] args) {
        return onDispatcherCalled(3, args);
    }

    public static Object callback_04(Object[] args) {
        return onDispatcherCalled(4, args);
    }

    public static Object callback_05(Object[] args) {
        return onDispatcherCalled(5, args);
    }

    public static Object callback_06(Object[] args) {
        return onDispatcherCalled(6, args);
    }

    public static Object callback_07(Object[] args) {
        return onDispatcherCalled(7, args);
    }

    public static Object callback_08(Object[] args) {
        return onDispatcherCalled(8, args);
    }

    public static Object callback_09(Object[] args) {
        return onDispatcherCalled(9, args);
    }
}
