package javax.jms;

/** Stub of the JMS API, for compiling the app fixtures (A6). */
public interface MessageListener {

    void onMessage(Message message) throws JMSException;
}
