package io.github.mtarek7900.tid.source;

import java.time.Instant;

/** How many of VirusTotal's engines flagged the Indicator as malicious in its last analysis. */
public record VirusTotalFacts(int enginesFlagged, int enginesTotal, Instant lastAnalysedAt) implements SourceFacts {}
