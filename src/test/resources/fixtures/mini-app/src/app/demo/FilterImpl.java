package demo;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import stublib.Stub;

/** Callback entry point (A13): a servlet filter. */
public class FilterImpl implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        new Stub().safe();
    }
}
