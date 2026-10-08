package demo;

import org.quartz.Job;

/** Interface extending the Quartz callback interface (transitive callback chain). */
public interface MyJob extends Job {
}
