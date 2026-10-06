package demo;

import stublib.Stub;

/** No superclass at all, yet a method named doGet: the superclass check is empty. */
public class NoSuper {

    public void doGet() {
        new Stub().safe();
    }
}
