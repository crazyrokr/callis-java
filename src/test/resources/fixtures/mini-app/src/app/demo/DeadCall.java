package demo;

/**
 * CHA-vs-RTA fixture (T33): a virtual call to a business interface that is
 * never instantiated. RTA prunes BusinessService.run (and the danger() call
 * inside it); CHA keeps it - the documented precision difference.
 */
public class DeadCall {

    public static void main(String[] args) {
        Business service = null;
        service.run();
    }
}
