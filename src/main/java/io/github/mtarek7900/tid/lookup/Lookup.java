package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.source.NotCheckedReason;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.SourceFacts;
import io.github.mtarek7900.tid.verdict.Signal;
import io.github.mtarek7900.tid.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * @param partial whether this is a Partial Verdict, reached without some of the Sources asked
 * @param sourcesNotChecked the Sources asked whose Source Result is Not Checked
 * @param why one line per Source Result, saying which Signal it gave and why
 * @param sourcesAsked the names of the Sources that cover the Indicator Type
 */
public record Lookup(
        UUID id,
        String indicator,
        IndicatorType indicatorType,
        Verdict verdict,
        boolean partial,
        List<String> sourcesNotChecked,
        List<String> why,
        List<String> sourcesAsked,
        List<UsedSourceResult> sourceResults,
        Instant lookedUpAt) {

    /**
     * A Source Result this Lookup used, with the Signal the Verdict rule read from it.
     *
     * @param reused whether an earlier Lookup fetched it, so this Lookup didn't ask the Source
     */
    public record UsedSourceResult(
            String source,
            Outcome outcome,
            NotCheckedReason notCheckedReason,
            Signal signal,
            SourceFacts facts,
            String link,
            Instant fetchedAt,
            boolean reused,
            String rawResponse) {}
}
