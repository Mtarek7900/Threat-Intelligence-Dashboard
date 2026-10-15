package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.lookup.Lookup.UsedSourceResult;
import io.github.mtarek7900.tid.source.Source;
import io.github.mtarek7900.tid.source.SourceResults;
import io.github.mtarek7900.tid.verdict.Decision;
import io.github.mtarek7900.tid.verdict.Reading;
import io.github.mtarek7900.tid.verdict.VerdictRule;
import io.github.mtarek7900.tid.verdict.VerdictThresholds;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
class LookupService {

    private final List<Source> sources;
    private final SourceResults sourceResults;
    private final VerdictRule verdictRule;
    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final Clock clock;

    LookupService(
            List<Source> sources,
            SourceResults sourceResults,
            VerdictThresholds thresholds,
            JdbcClient jdbc,
            TransactionTemplate transactions,
            Clock clock) {
        this.sources = sources;
        this.sourceResults = sourceResults;
        this.verdictRule = new VerdictRule(thresholds);
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** Asks every Source that covers the Indicator Type, then keeps the Lookup and the Source Results it used. */
    Lookup lookUp(UUID analystId, Indicator indicator) {
        var asked = sources.stream()
                .filter(source -> source.indicatorTypes().contains(indicator.type()))
                .toList();
        var results = asked.stream().map(source -> source.fetch(indicator)).toList();
        var decision = verdictRule.decide(results);
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var lookedUpAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        var lookup = new Lookup(
                UUID.randomUUID(),
                indicator.value(),
                indicator.type(),
                decision.verdict(),
                decision.readings().stream().map(Reading::explanation).toList(),
                asked.stream().map(Source::name).toList(),
                decision.readings().stream().map(LookupService::used).toList(),
                lookedUpAt);
        transactions.executeWithoutResult(status -> keep(analystId, lookup, decision));
        return lookup;
    }

    private void keep(UUID analystId, Lookup lookup, Decision decision) {
        jdbc.sql("""
                        insert into lookup (id, analyst_id, indicator, indicator_type, verdict, partial, looked_up_at)
                        values (:id, :analystId, :indicator, :indicatorType, :verdict, false, :lookedUpAt)
                        """)
                .param("id", lookup.id())
                .param("analystId", analystId)
                .param("indicator", lookup.indicator())
                .param("indicatorType", lookup.indicatorType().name())
                .param("verdict", lookup.verdict().name())
                .param("lookedUpAt", lookup.lookedUpAt().atOffset(ZoneOffset.UTC))
                .update();
        for (var reading : decision.readings()) {
            sourceResults.add(reading.result());
            jdbc.sql("""
                            insert into lookup_source_result (lookup_id, source_result_id, signal, explanation)
                            values (:lookupId, :sourceResultId, :signal, :explanation)
                            """)
                    .param("lookupId", lookup.id())
                    .param("sourceResultId", reading.result().id())
                    .param("signal", reading.signal().name())
                    .param("explanation", reading.explanation())
                    .update();
        }
    }

    private static UsedSourceResult used(Reading reading) {
        var result = reading.result();
        return new UsedSourceResult(
                result.source(),
                result.outcome(),
                reading.signal(),
                result.facts(),
                result.link(),
                result.fetchedAt(),
                result.rawResponse());
    }
}
