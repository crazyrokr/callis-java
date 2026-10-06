package demo;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import stublib.Stub;

/** Implements the JMS callback directly. */
public class BaseListener implements MessageListener {

    @Override
    public void onMessage(Message message) throws JMSException {
        new Stub().safe();
    }
}
