package demo;

/**
 * M7b SPARK fixture (the discriminator): DangerImpl is instantiated (by
 * assignment, as SootUp's RTA counts) but never dispatched at the
 * reference.op() site. SootUp's RTA keeps it (instantiation is tracked
 * per program, not per receiver - the false positive); SPARK's
 * per-receiver points-to analysis prunes it (the true negative).
 */
public class PointerDemo2 {

    public static void main(String[] args) {
        PIface reference = new SafeImpl();
        reference.op();
        PIface candidate = new DangerImpl();
        Object leftover = keep(candidate);
    }

    private static Object keep(PIface candidate) {
        return candidate;
    }
}
