package demo;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
import stublib.Stub;

/** Annotation entry point (A6): @RabbitListener method. */
public class RabbitConsumer {

    @RabbitListener
    public void onMessage(String payload) {
        new Stub().safe();
    }
}
