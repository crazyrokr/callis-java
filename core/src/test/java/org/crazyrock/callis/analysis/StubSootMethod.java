package org.crazyrock.callis.analysis;

import sootup.core.frontend.BodySource;
import sootup.core.frontend.OverridingBodySource;
import sootup.core.IdentifierFactory;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;
import sootup.core.model.Position;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.MethodSubSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.core.util.printer.StmtPrinter;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Test double for the {@link SootMethod} model interface (neither
 * {@code JavaSootMethod} nor {@code HasAnnotation}): every method the
 * {@code EntryPointDetector} does not exercise returns an inert default, so
 * the annotation fallbacks can be tested with non-Java model objects.
 */
public class StubSootMethod implements SootMethod {

    private final String name;

    public StubSootMethod(String name) {
        this.name = name;
    }

    @Override
    public Set<MethodModifier> getModifiers() {
        return Set.of();
    }

    @Override
    public MethodSignature getSignature() {
        return null;
    }

    @Override
    public boolean isProtected() {
        return false;
    }

    @Override
    public boolean isPrivate() {
        return false;
    }

    @Override
    public boolean isPublic() {
        return false;
    }

    @Override
    public boolean isStatic() {
        return false;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public boolean isAbstract() {
        return false;
    }

    @Override
    public boolean isNative() {
        return false;
    }

    @Override
    public boolean isSynchronized() {
        return false;
    }

    @Override
    public boolean isConcrete() {
        return true;
    }

    @Override
    public boolean hasBody() {
        return false;
    }

    @Override
    public Body getBody() {
        return null;
    }

    @Override
    public Type getReturnType() {
        return null;
    }

    @Override
    public int getParameterCount() {
        return 0;
    }

    @Override
    public Type getParameterType(int index) {
        return null;
    }

    @Override
    public List<Type> getParameterTypes() {
        return List.of();
    }

    @Override
    public MethodSubSignature getSubSignature() {
        return null;
    }

    @Override
    public ClassType getDeclClassType() {
        return null;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public List<ClassType> getExceptionSignatures() {
        return List.of();
    }

    @Override
    public BodySource getBodySource() {
        return null;
    }

    @Override
    public boolean isMain(IdentifierFactory identifierFactory) {
        return false;
    }

    @Override
    public boolean isConstructor(IdentifierFactory identifierFactory) {
        return false;
    }

    @Override
    public boolean isDefaultConstructor(IdentifierFactory identifierFactory) {
        return false;
    }

    @Override
    public void toString(StmtPrinter printer) {
    }

    @Override
    public SootMethod withOverridingMethodSource(
            Function<OverridingBodySource, OverridingBodySource> overrider) {
        return this;
    }

    @Override
    public SootMethod withSource(BodySource source) {
        return this;
    }

    @Override
    public SootMethod withModifiers(Iterable<MethodModifier> modifiers) {
        return this;
    }

    @Override
    public SootMethod withThrownExceptions(Iterable<ClassType> exceptions) {
        return this;
    }

    @Override
    public SootMethod withBody(Body body) {
        return this;
    }

    @Override
    public Position getPosition() {
        return null;
    }

    @Override
    public ClassType getDeclaringClassType() {
        return null;
    }
}
