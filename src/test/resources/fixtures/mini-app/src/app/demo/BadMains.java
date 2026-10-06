package demo;

/**
 * main() signature traps (M3 branch coverage): every overload is named main
 * but none is {@code main(String[])}, so none is an entry point.
 */
public class BadMains {

    public static void main(String arg, int other) {
    }

    public static void main(int arg) {
    }

    public static void main(int[] args) {
    }

    public static void main(String[][] args) {
    }

    public static void main(Object[] args) {
    }
}
