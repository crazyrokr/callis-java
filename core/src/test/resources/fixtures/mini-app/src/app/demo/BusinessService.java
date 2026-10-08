package demo;

import stublib.Marked;
import stublib.Stub;

/** Implements a plain business interface only - not an entry point (A13 precision guard). */
public class BusinessService implements Business {

    /** @Marked is a non-handler annotation: it must not turn run() into an entry point. */
    @Override
    @Marked
    public void run() {
        new Stub().danger();
    }
}
