package io.github.mtarek7900.tid.source;

import io.github.mtarek7900.tid.indicator.Indicator;
import java.time.Instant;
import java.util.UUID;

/**
 * What one Source reported about one Indicator at {@code fetchedAt}. Never changed once stored.
 *
 * @param notCheckedReason why the Source wasn't asked or couldn't answer; null unless Not Checked
 * @param facts what the Source reported, or null unless it has Seen the Indicator
 * @param link the Indicator's page on the Source's own site
 * @param rawResponse the Source's response body, exactly as received; null when Not Checked
 */
public record SourceResult(
        UUID id,
        String source,
        Indicator indicator,
        Outcome outcome,
        NotCheckedReason notCheckedReason,
        SourceFacts facts,
        String link,
        String rawResponse,
        Instant fetchedAt) {}
