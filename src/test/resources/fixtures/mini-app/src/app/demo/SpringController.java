package demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import stublib.Stub;

/** Annotation entry point (A6): @RestController + @GetMapping handler. */
@RestController
public class SpringController {

    @GetMapping("/data")
    public String data() {
        new Stub().safe();
        return "ok";
    }
}
