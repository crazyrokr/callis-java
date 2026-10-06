package org.quartz;

/** Stub of the Quartz API, for compiling the app fixtures (A13). */
public interface Job {

    void execute(JobExecutionContext context);
}
