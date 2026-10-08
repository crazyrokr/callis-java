package demo;

import stublib.Stub;

/**
 * Extends a non-HttpServlet class but declares a method named doGet: the
 * superclass check must match neither servlet base class.
 */
public class OddServlet extends Stub {

    public void doGet() {
        new Stub().safe();
    }
}
