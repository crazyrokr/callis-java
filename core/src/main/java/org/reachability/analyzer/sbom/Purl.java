package org.reachability.analyzer.sbom;

import java.util.Locale;
import java.util.Objects;

/**
 * A Software Package URI (purl) in the form
 * {@code pkg:type/namespace/name@version?qualifiers#subpath}.
 *
 * <p>OSV purls may omit the version; some maven purls omit the namespace
 * (group). Qualifiers and subpath are kept raw and play no role in matching.
 */
public final class Purl {

    private final String type;
    private final String namespace;
    private final String name;
    private final String version;
    private final String qualifiers;
    private final String subpath;

    private Purl(String type, String namespace, String name,
                 String version, String qualifiers, String subpath) {
        this.type = type;
        this.namespace = namespace;
        this.name = name;
        this.version = version;
        this.qualifiers = qualifiers;
        this.subpath = subpath;
    }

    public static Purl parse(String purl) {
        Objects.requireNonNull(purl, "purl must not be null");
        if (!purl.startsWith("pkg:")) {
            throw new IllegalArgumentException("not a purl (missing 'pkg:' prefix): " + purl);
        }
        String remainder = purl.substring(4);

        String subpath = null;
        int hash = remainder.indexOf('#');
        if (hash >= 0) {
            subpath = remainder.substring(hash + 1);
            remainder = remainder.substring(0, hash);
        }

        String qualifiers = null;
        int question = remainder.indexOf('?');
        if (question >= 0) {
            qualifiers = remainder.substring(question + 1);
            remainder = remainder.substring(0, question);
        }

        String version = null;
        // The last '@': names may themselves contain '@' (e.g. npm scoped names).
        int at = remainder.lastIndexOf('@');
        if (at >= 0) {
            version = remainder.substring(at + 1);
            remainder = remainder.substring(0, at);
            if (version.isEmpty()) {
                version = null;
            }
        }

        int typeSlash = remainder.indexOf('/');
        String type;
        String path;
        if (typeSlash < 0) {
            type = remainder;
            path = "";
        } else {
            type = remainder.substring(0, typeSlash);
            path = remainder.substring(typeSlash + 1);
        }
        if (type.isEmpty()) {
            throw new IllegalArgumentException("not a purl (empty type): " + purl);
        }

        String namespace = "";
        String name = path;
        int slash = path.indexOf('/');
        if (slash >= 0) {
            namespace = path.substring(0, slash);
            name = path.substring(slash + 1);
        }
        if (name.isEmpty()) {
            throw new IllegalArgumentException("not a purl (empty name): " + purl);
        }

        return new Purl(type.toLowerCase(Locale.ROOT), namespace, name, version, qualifiers, subpath);
    }

    public String getType() {
        return type;
    }

    public boolean isMaven() {
        return "maven".equals(type);
    }

    public String getNamespace() {
        return namespace;
    }

    public String getName() {
        return name;
    }

    /** Version, or null when the purl carries none (common in OSV records). */
    public String getVersion() {
        return version;
    }

    public String getQualifiers() {
        return qualifiers;
    }

    public String getSubpath() {
        return subpath;
    }

    /** "group:name" for namespaced purls, plain name otherwise. */
    public String getQualifiedName() {
        return namespace.isEmpty() ? name : namespace + ":" + name;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder("pkg:").append(type).append('/');
        if (!namespace.isEmpty()) {
            out.append(namespace).append('/');
        }
        out.append(name);
        if (version != null) {
            out.append('@').append(version);
        }
        if (qualifiers != null) {
            out.append('?').append(qualifiers);
        }
        if (subpath != null) {
            out.append('#').append(subpath);
        }
        return out.toString();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Purl)) {
            return false;
        }
        Purl that = (Purl) other;
        return type.equals(that.type) && namespace.equals(that.namespace)
                && name.equals(that.name) && Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, namespace, name, version);
    }
}
