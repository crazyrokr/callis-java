package javax.servlet;

/** Stub of the Servlet API, for compiling the app fixtures (A13). */
public interface Filter {

    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain);
}
