package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.lookup.Lookup.UsedSourceResult;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.SourceResults;
import io.github.mtarek7900.tid.verdict.Signal;
import io.github.mtarek7900.tid.verdict.Verdict;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class LookupHistory {

    private final JdbcClient jdbc;
    private final SourceResults sourceResults;

    LookupHistory(JdbcClient jdbc, SourceResults sourceResults) {
        this.jdbc = jdbc;
        this.sourceResults = sourceResults;
    }

    /** The Analyst's Lookups grouped by Indicator, the group with the most recent Lookup first. */
    List<LookupHistoryGroup> of(UUID analystId) {
        var lookups = jdbc.sql("""
                        select id, indicator, indicator_type, verdict, looked_up_at
                        from lookup
                        where analyst_id = :analystId
                        order by looked_up_at desc
                        """)
                .param("analystId", analystId)
                .query(LookupHistoryEntry.class)
                .list();
        return lookups.stream()
                .collect(Collectors.groupingBy(
                        lookup -> new Indicator(lookup.indicator(), lookup.indicatorType()),
                        LinkedHashMap::new,
                        Collectors.toList()))
                .values()
                .stream()
                .map(LookupHistoryGroup::of)
                .toList();
    }

    /**
     * The Analyst's Lookup as it was made: its stored Verdict, and the Source Results it used with
     * the Signal and "Why?" line each gave at the time, however many newer ones exist since.
     */
    Optional<Lookup> find(UUID analystId, UUID lookupId) {
        return jdbc.sql("""
                        select indicator, indicator_type, verdict, partial, looked_up_at
                        from lookup
                        where id = :id and analyst_id = :analystId
                        """)
                .param("id", lookupId)
                .param("analystId", analystId)
                .query((row, rowNumber) -> new StoredLookup(
                        new Indicator(row.getString("indicator"), IndicatorType.valueOf(row.getString("indicator_type"))),
                        Verdict.valueOf(row.getString("verdict")),
                        row.getBoolean("partial"),
                        row.getObject("looked_up_at", OffsetDateTime.class).toInstant()))
                .optional()
                .map(stored -> withSourceResults(lookupId, stored));
    }

    private Lookup withSourceResults(UUID lookupId, StoredLookup stored) {
        var rows = jdbc.sql("""
                        select source_result_id, signal, explanation, reused
                        from lookup_source_result
                        where lookup_id = :lookupId
                        order by position
                        """)
                .param("lookupId", lookupId)
                .query(LinkedSourceResult.class)
                .list();
        var byId = sourceResults.withIds(
                stored.indicator(), rows.stream().map(LinkedSourceResult::sourceResultId).toList());
        var used = rows.stream()
                .map(row -> UsedSourceResult.of(byId.get(row.sourceResultId()), row.signal(), row.reused()))
                .toList();
        return new Lookup(
                lookupId,
                stored.indicator().value(),
                stored.indicator().type(),
                stored.verdict(),
                stored.partial(),
                used.stream()
                        .filter(result -> result.outcome() == Outcome.NOT_CHECKED)
                        .map(UsedSourceResult::source)
                        .toList(),
                rows.stream().map(LinkedSourceResult::explanation).toList(),
                // Every Source asked gives the Lookup one Source Result, Not Checked if it couldn't answer
                used.stream().map(UsedSourceResult::source).toList(),
                used,
                stored.lookedUpAt());
    }

    private record StoredLookup(Indicator indicator, Verdict verdict, boolean partial, Instant lookedUpAt) {}

    private record LinkedSourceResult(UUID sourceResultId, Signal signal, String explanation, boolean reused) {}
}
