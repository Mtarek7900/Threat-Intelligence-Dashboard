package io.github.mtarek7900.tid.source;

import io.github.mtarek7900.tid.indicator.Indicator;
import java.time.Instant;
import java.util.UUID;

/**
 * What one Source reported about one Indicator at {@code fetchedAt}. Never changed once stored.
 *
 * @param facts what the Source reported, or null when it has Not Seen the Indicator
 * @param link the Indicator's page on the Source's own site
 * @param rawResponse the Source's response body, exactly as received
 */
public record SourceResult(
        UUID id,
        String source,
        Indicator indicator,
        Outcome outcome,
        SourceFacts facts,
        String link,
        String rawResponse,
        Instant fetchedAt) {}
