package io.github.mtarek7900.tid.source;

/** The key facts a Source reported about an Indicator it has Seen, shown on its panel. */
public sealed interface SourceFacts permits VirusTotalFacts, AbuseIpdbFacts, OtxFacts {

    /** Whether these come from a Corroborating Source, whose Signal never decides the Verdict alone. */
    default boolean fromCorroboratingSource() {
        return false;
    }
}
