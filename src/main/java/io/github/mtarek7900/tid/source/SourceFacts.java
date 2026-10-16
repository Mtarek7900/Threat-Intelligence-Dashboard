package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/** The key facts a Source reported about an Indicator it has Seen, shown on its panel. */
// Stored facts are read back by which fields they have, so neither they nor the API carry a type name
@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(VirusTotalFacts.class),
    @JsonSubTypes.Type(AbuseIpdbFacts.class),
    @JsonSubTypes.Type(OtxFacts.class)
})
public sealed interface SourceFacts permits VirusTotalFacts, AbuseIpdbFacts, OtxFacts {

    /** Whether these come from a Corroborating Source, whose Signal never decides the Verdict alone. */
    default boolean fromCorroboratingSource() {
        return false;
    }
}
