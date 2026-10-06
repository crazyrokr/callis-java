package demo;

import jakarta.servlet.annotation.WebServlet;
import stublib.Stub;

/** Jakarta @WebServlet annotation (the jakarta half of the annotation check). */
@jakarta.servlet.annotation.WebServlet("/jakarta")
public class JakartaWebServlet {

    public void doGet() {
        new Stub().safe();
    }
}
