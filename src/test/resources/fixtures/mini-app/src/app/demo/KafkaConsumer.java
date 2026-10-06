package demo;

import org.springframework.kafka.annotation.KafkaListener;
import stublib.Stub;

/** Annotation entry point (A6): @KafkaListener method. */
public class KafkaConsumer {

    @KafkaListener(topics = "events")
    public void onRecord(String record) {
        new Stub().safe();
    }
}
