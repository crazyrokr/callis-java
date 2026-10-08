package demo;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import stublib.Stub;

/** Callback entry point (A13): a JMS message listener. */
public class JmsListener implements MessageListener {

    @Override
    public void onMessage(Message message) throws JMSException {
        new Stub().safe();
    }
}
