package org.crazyrock.callis.sbom;

import java.util.Objects;

/** One component entry of a parsed SBOM. */
public final class SbomComponent {

    private final String name;
    private final String version;
    private final Purl purl;
    private final String bomRef;

    public SbomComponent(String name, String version, Purl purl, String bomRef) {
        this.name = Objects.requireNonNull(name, "name");
        this.version = version;
        this.purl = Objects.requireNonNull(purl, "purl");
        this.bomRef = bomRef;
    }

    public String getName() {
        return name;
    }

    /** Version as declared in the SBOM, or null when the SBOM omits it. */
    public String getVersion() {
        return version;
    }

    public Purl getPurl() {
        return purl;
    }

    /** The bom-ref when present; auto-generated "bom-..." refs carry no meaning and are ignored. */
    public String getBomRef() {
        return bomRef;
    }

    @Override
    public String toString() {
        return name + (version != null ? ":" + version : "") + " (" + purl + ")";
    }
}
