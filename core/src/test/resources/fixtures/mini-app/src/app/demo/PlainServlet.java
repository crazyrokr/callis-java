package demo;

import javax.servlet.http.HttpServlet;
import org.springframework.stereotype.Controller;
import stublib.Stub;

/** @Controller (a non-WebServlet class annotation) + HttpServlet superclass. */
@Controller
public class PlainServlet extends HttpServlet {

    protected void doGet() {
        new Stub().safe();
    }
}
