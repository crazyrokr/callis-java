package demo;

import stublib.Stub;

/** mini-app entry: calls the stub's dangerous method. */
public class MainDanger {

    public static void main(String[] args) {
        new Stub().danger();
    }
}
