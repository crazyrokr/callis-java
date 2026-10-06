package demo;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import stublib.Stub;

/** HttpServlet subclass without @WebServlet: entry via the superclass check. */
public class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        new Stub().safe();
    }
}
