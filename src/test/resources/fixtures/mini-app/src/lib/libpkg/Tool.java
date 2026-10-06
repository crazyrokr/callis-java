package libpkg;

import stublib.Stub;

/**
 * Library class that happens to have a main(). Lives in stublib.jar, NOT in the
 * app class directory, so its main() must never be detected as an app entry
 * point (T32: main() in app classes only, never library mains).
 */
public class Tool {

    public static void main(String[] args) {
        new Stub().safe();
    }
}
