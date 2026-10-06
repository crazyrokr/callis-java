package demo;

import org.quartz.JobExecutionContext;
import stublib.Stub;

/** Implements MyJob, which extends Job: callback detected through the interface chain. */
public class MyJobImpl implements MyJob {

    @Override
    public void execute(JobExecutionContext context) {
        new Stub().safe();
    }
}
