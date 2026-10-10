package org.reachability.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.file.Directory;
import org.gradle.api.file.RegularFile;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.SourceSetContainer;

import java.io.File;
import java.nio.file.Path;
import java.util.Set;

/**
 * A10 (M7e): the reachability front end for Gradle. Applies the
 * {@code reachability} extension and the {@code checkReachability} task to a
 * project with the java plugin; the task analyzes the main source set
 * against the project's SBOM and OSV snapshot in-process (the core engine)
 * and fails the build when any vulnerability is reachable.
 */
public class ReachabilityPlugin implements Plugin<Project> {

    public static final String EXTENSION_NAME = "reachability";
    public static final String TASK_NAME = "checkReachability";
    public static final String DEFAULT_REPORT_BASE = "reachability-report";

    @Override
    public void apply(Project project) {
        // Gradle 9.8 removed PluginManager.hasPlugin(Class); "java" is the plugin id
        // and is applied by both the java and the java-library plugin.
        if (!project.getPluginManager().hasPlugin("java")) {
            throw new IllegalStateException("the reachability plugin requires the java plugin "
                    + "(apply 'java' before 'org.reachability')");
        }

        ReachabilityExtension extension =
                project.getExtensions().create(EXTENSION_NAME, ReachabilityExtension.class);
        extension.getBomFile().convention("");
        extension.getOsvDir().convention("");
        extension.getExpectedOsvChecksum().convention("");
        extension.getMappings().convention("");
        extension.getCha().convention(false);
        extension.getPointerAnalysis().convention(false);
        extension.getFormats().convention("json,junitxml");

        SourceSet main = project.getExtensions().getByType(SourceSetContainer.class)
                .getByName(SourceSet.MAIN_SOURCE_SET_NAME);

        project.getTasks().register(TASK_NAME, CheckReachabilityTask.class, task -> {
            task.setGroup("verification");
            task.setDescription("Fails the build when a vulnerability from the project's SBOM is "
                    + "reachable from the main source set (A10).");
            task.dependsOn(project.getTasks().named(JavaPlugin.COMPILE_JAVA_TASK_NAME));
            task.getAppClasses().set(mainClassesDirectory(project, main));
            task.getClasspathJars().from(project.getConfigurations().getByName("runtimeClasspath"));
            task.getBomFile().set(extension.getBomFile());
            task.getOsvDir().set(extension.getOsvDir());
            task.getExpectedOsvChecksum().set(extension.getExpectedOsvChecksum());
            task.getMappings().set(extension.getMappings());
            task.getEntryPoints().set(extension.getEntryPoints());
            task.getCallbackInterfaces().set(extension.getCallbackInterfaces());
            task.getCha().set(extension.getCha());
            task.getPointerAnalysis().set(extension.getPointerAnalysis());
            task.getFormats().set(extension.getFormats());
            task.getReportBase().convention(DEFAULT_REPORT_BASE);
            task.getBomFileContent().set(contentFile(project, task.getBomFile()));
            task.getOsvDirContent().set(contentDir(project, task.getOsvDir()));
            task.getMappingsContent().set(contentFile(project, task.getMappings()));
        });
    }

    /**
     * A path property as task input content: blank is absent, relative paths
     * resolve against the project directory, so a file or directory edited
     * in place invalidates the task.
     */
    private Provider<RegularFile> contentFile(Project project, Property<String> path) {
        return path.filter(value -> !value.isBlank())
                .map(value -> resolve(project, value))
                .flatMap(file -> project.getLayout().file(project.provider(() -> file)));
    }

    private Provider<Directory> contentDir(Project project, Property<String> path) {
        return path.filter(value -> !value.isBlank())
                .map(value -> resolve(project, value))
                .flatMap(dir -> project.getLayout().dir(project.provider(() -> dir)));
    }

    /**
     * Relative paths resolve against the project directory; absolute paths
     * pass through; the result is lexically normalized. (JDK 25's two-arg
     * File constructor also joins absolute children, so Path.resolve is used.)
     */
    private File resolve(Project project, String path) {
        Path p = Path.of(path);
        Path resolved = p.isAbsolute()
                ? p : project.getProjectDir().toPath().resolve(p);
        return resolved.normalize().toFile();
    }

    /**
     * The main source set's classes directory. Standard java layouts have
     * exactly one; multi-output layouts are not supported yet (explicit
     * error at task execution).
     */
    private Provider<Directory> mainClassesDirectory(Project project, SourceSet main) {
        return project.getLayout().dir(project.provider(() -> {
            Set<File> classesDirs = main.getOutput().getClassesDirs().getFiles();
            if (classesDirs.size() != 1) {
                throw new IllegalStateException("the main source set has " + classesDirs.size()
                        + " class directories; exactly one is required");
            }
            return classesDirs.iterator().next();
        }));
    }
}
