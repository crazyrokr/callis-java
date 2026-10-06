package demo;

import stublib.Stub;

/** mini-app entry: calls the stub's safe method only (RTA prunes danger). */
public class Main {

    public static void main(String[] args) {
        new Stub().safe();
    }
}
