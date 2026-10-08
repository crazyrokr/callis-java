package demo;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import stublib.Stub;

/** Annotation entry point (A6): @WebServlet servlet with doGet/doPost. */
@WebServlet("/web")
public class WebController extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        new Stub().safe();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        new Stub().safe();
    }
}
