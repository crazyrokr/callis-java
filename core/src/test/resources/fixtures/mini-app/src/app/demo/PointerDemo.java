package demo;

/**
 * M7b flagship false-positive pin: ref.op() resolves to SafeImpl only at
 * runtime (the only allocation). RTA also pulls in DangerImpl.op ->
 * Stub.danger (false positive); SPARK prunes it (true negative).
 */
public class PointerDemo {

    public static void main(String[] args) {
        PIface reference = new SafeImpl();
        reference.op();
    }
}
