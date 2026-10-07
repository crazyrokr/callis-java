package demo;

import stublib.Stub;

/** Concrete service whose method calls the stub's dangerous method (M4 positive path). */
public class VulnService {

    public void work() {
        new Stub().danger();
    }
}
