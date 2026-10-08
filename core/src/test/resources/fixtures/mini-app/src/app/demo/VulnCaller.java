package demo;

/** M4 positive: main - VulnService.work - stublib.Stub.danger (three hops, RTA-resolvable). */
public class VulnCaller {

    public static void main(String[] args) {
        new VulnService().work();
    }
}
