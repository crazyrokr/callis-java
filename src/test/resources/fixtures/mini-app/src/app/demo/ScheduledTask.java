package demo;

import org.springframework.scheduling.annotation.Scheduled;
import stublib.Stub;

/** Annotation entry point (A6): @Scheduled method. */
public class ScheduledTask {

    @Scheduled(cron = "0 0 * * * *")
    public void tick() {
        new Stub().safe();
    }
}
