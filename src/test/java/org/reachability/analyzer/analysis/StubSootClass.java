package org.reachability.analyzer.analysis;

import sootup.core.frontend.SootClassSource;
import sootup.core.model.ClassModifier;
import sootup.core.model.Position;
import sootup.core.model.SootClass;
import sootup.core.model.SootField;
import sootup.core.model.SootMethod;
import sootup.core.signatures.FieldSubSignature;
import sootup.core.signatures.MethodSubSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;

import java.util.Optional;
import java.util.Set;

/**
 * Test double for the {@link SootClass} model interface (neither
 * {@code JavaSootClass} nor {@code HasAnnotation}): every method the
 * {@code EntryPointDetector} does not exercise returns an inert default, so
 * the annotation fallbacks can be tested with non-Java model objects.
 */
public class StubSootClass implements SootClass {

    private final String name;
    private final Set<SootMethod> methods;
    private final Set<ClassType> interfaces;
    private final Optional<ClassType> superclass;

    public StubSootClass(String name, Set<SootMethod> methods, Set<ClassType> interfaces,
                         Optional<ClassType> superclass) {
        this.name = name;
        this.methods = methods;
        this.interfaces = interfaces;
        this.superclass = superclass;
    }

    @Override
    public SootClassSource getClassSource() {
        return null;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public ClassType getType() {
        return null;
    }

    @Override
    public Set<SootField> getFields() {
        return Set.of();
    }

    @Override
    public Set<SootMethod> getMethods() {
        return methods;
    }

    @Override
    public Optional<SootMethod> getMethod(MethodSubSignature subSignature) {
        return Optional.empty();
    }

    @Override
    public Optional<SootField> getField(FieldSubSignature subSignature) {
        return Optional.empty();
    }

    @Override
    public Optional<SootField> getField(String fieldName) {
        return Optional.empty();
    }

    @Override
    public Optional<SootMethod> getMethod(String methodName, Iterable<? extends Type> parameterTypes) {
        return Optional.empty();
    }

    @Override
    public Set<SootMethod> getMethodsByName(String methodName) {
        Set<SootMethod> byName = new java.util.HashSet<>();
        for (SootMethod method : methods) {
            if (method.getName().equals(methodName)) {
                byName.add(method);
            }
        }
        return byName;
    }

    @Override
    public Set<ClassModifier> getModifiers() {
        return Set.of();
    }

    @Override
    public Set<ClassType> getInterfaces() {
        return interfaces;
    }

    @Override
    public Optional<ClassType> getOuterClass() {
        return Optional.empty();
    }

    @Override
    public Optional<ClassType> getSuperclass() {
        return superclass;
    }

    @Override
    public boolean isInterface() {
        return false;
    }

    @Override
    public boolean isEnum() {
        return false;
    }

    @Override
    public boolean isSuper() {
        return false;
    }

    @Override
    public boolean isConcrete() {
        return true;
    }

    @Override
    public boolean isPublic() {
        return false;
    }

    @Override
    public boolean isApplicationClass() {
        return false;
    }

    @Override
    public boolean isLibraryClass() {
        return false;
    }

    @Override
    public boolean isPrivate() {
        return false;
    }

    @Override
    public boolean isProtected() {
        return false;
    }

    @Override
    public boolean isAbstract() {
        return false;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public boolean isStatic() {
        return false;
    }

    @Override
    public boolean isAnnotation() {
        return false;
    }

    @Override
    public boolean isInnerClass() {
        return false;
    }

    @Override
    public boolean hasSuperclass() {
        return superclass.isPresent();
    }

    @Override
    public boolean hasOuterClass() {
        return false;
    }

    @Override
    public Position getPosition() {
        return null;
    }

    @Override
    public String print() {
        return name;
    }
}
