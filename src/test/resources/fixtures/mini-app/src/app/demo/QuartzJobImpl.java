package demo;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import stublib.Stub;

/** Callback entry point (A13): a Quartz job reaches the dangerous method. */
public class QuartzJobImpl implements Job {

    @Override
    public void execute(JobExecutionContext context) {
        new Stub().danger();
    }
}
