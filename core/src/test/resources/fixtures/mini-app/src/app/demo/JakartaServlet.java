package demo;

import jakarta.servlet.http.HttpServlet;
import stublib.Stub;

/** jakarta HttpServlet subclass: the superclass check matches the jakarta name. */
public class JakartaServlet extends HttpServlet {

    @Override
    protected void doGet() {
        new Stub().safe();
    }
}
