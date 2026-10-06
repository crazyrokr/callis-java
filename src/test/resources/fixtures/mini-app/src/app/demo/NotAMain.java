package demo;

import stublib.Stub;

/** Name trap: a non-static main(String[]) and a static main(int) - neither is a JVM entry. */
public class NotAMain {

    public void main(String[] args) {
        new Stub().safe();
    }

    public static void main(int arg) {
        new Stub().safe();
    }
}
