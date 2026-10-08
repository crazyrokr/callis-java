package demo;

import javax.jms.JMSException;
import javax.jms.Message;
import stublib.Stub;

/** Extends BaseListener: callback detected through the superclass chain. */
public class AdvancedListener extends BaseListener {

    @Override
    public void onMessage(Message message) throws JMSException {
        new Stub().safe();
    }
}
