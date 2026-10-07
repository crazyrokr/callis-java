package demo;

/** M4 determinism: second caller at the same distance as VulnCaller (lexicographic tie-break). */
public class VulnCaller2 {

    public static void main(String[] args) {
        new VulnService().work();
    }
}
