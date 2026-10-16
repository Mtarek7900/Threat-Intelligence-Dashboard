package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.lookup.Lookup.UsedSourceResult;
import io.github.mtarek7900.tid.source.NotCheckedReason;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.Source;
import io.github.mtarek7900.tid.source.SourceException;
import io.github.mtarek7900.tid.source.SourceResult;
import io.github.mtarek7900.tid.source.SourceResults;
import io.github.mtarek7900.tid.source.SourcesProperties;
import io.github.mtarek7900.tid.verdict.Reading;
import io.github.mtarek7900.tid.verdict.VerdictRule;
import io.github.mtarek7900.tid.verdict.VerdictThresholds;
import jakarta.annotation.PreDestroy;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
class LookupService {

    private static final Logger log = LoggerFactory.getLogger(LookupService.class);

    private final List<Source> sources;
    private final Duration sourceTimeout;
    private final Duration reuseWindow;
    private final SourceResults sourceResults;
    private final VerdictRule verdictRule;
    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final Clock clock;
    // Not closed per Lookup: closing waits for every call, including one that has already timed out
    private final ExecutorService sourceCalls = Executors.newVirtualThreadPerTaskExecutor();

    LookupService(
            List<Source> sources,
            SourcesProperties sourcesProperties,
            SourceResults sourceResults,
            VerdictThresholds thresholds,
            JdbcClient jdbc,
            TransactionTemplate transactions,
            Clock clock) {
        this.sources = sources;
        this.sourceTimeout = sourcesProperties.timeout();
        this.reuseWindow = sourcesProperties.reuseWindow();
        this.sourceResults = sourceResults;
        this.verdictRule = new VerdictRule(thresholds);
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Reuses each Source's newest Source Result younger than the reuse window, unless refreshing,
     * and asks every other Source that covers the Indicator Type at the same time. Then keeps the
     * Lookup and the Source Results it used. A Source that can't answer in time gives a Not Checked
     * Source Result.
     *
     * @param refresh whether to ask every Source again, however recent its newest Source Result
     */
    Lookup lookUp(UUID analystId, Indicator indicator, boolean refresh) {
        var asked = sources.stream()
                .filter(source -> source.indicatorTypes().contains(indicator.type()))
                .toList();
        var reusableBySource = refresh
                ? Map.<String, SourceResult>of()
                : sourceResults.newestReusable(indicator, clock.instant().minus(reuseWindow));
        var calls = asked.stream()
                .map(source -> Optional.ofNullable(reusableBySource.get(source.name()))
                        .map(CompletableFuture::completedFuture)
                        .orElseGet(() -> ask(source, indicator)))
                .toList();
        var results = calls.stream().map(CompletableFuture::join).toList();
        var reusedIds = reusableBySource.values().stream()
                .map(SourceResult::id)
                .collect(Collectors.toUnmodifiableSet());
        var decision = verdictRule.decide(results);
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var lookedUpAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        var lookup = new Lookup(
                UUID.randomUUID(),
                indicator.value(),
                indicator.type(),
                decision.verdict(),
                decision.partial(),
                decision.notChecked(),
                decision.readings().stream().map(Reading::explanation).toList(),
                asked.stream().map(Source::name).toList(),
                decision.readings().stream()
                        .map(reading -> used(reading, reusedIds.contains(reading.result().id())))
                        .toList(),
                lookedUpAt);
        transactions.executeWithoutResult(status -> keep(analystId, lookup, decision.readings()));
        return lookup;
    }

    private CompletableFuture<SourceResult> ask(Source source, Indicator indicator) {
        return CompletableFuture.supplyAsync(() -> source.fetch(indicator), sourceCalls)
                .orTimeout(sourceTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .exceptionally(failure -> notChecked(source, indicator, reasonFor(source, failure)));
    }

    @PreDestroy
    void stopAskingSources() {
        sourceCalls.shutdownNow();
    }

    private static NotCheckedReason reasonFor(Source source, Throwable failure) {
        var cause = failure instanceof CompletionException ? failure.getCause() : failure;
        if (timedOut(cause)) {
            return NotCheckedReason.TIMEOUT;
        }
        return switch (cause) {
            case SourceException sourceException -> {
                log.warn("{} was Not Checked: {}", source.name(), sourceException.getMessage());
                yield sourceException.reason();
            }
            default -> {
                log.warn("{} was Not Checked", source.name(), cause);
                yield NotCheckedReason.SOURCE_ERROR;
            }
        };
    }

    /** The Lookup stopped waiting, or the Source's own HTTP client gave up first. */
    private static boolean timedOut(Throwable failure) {
        for (var cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof TimeoutException
                    || cause instanceof HttpTimeoutException
                    || cause instanceof SocketTimeoutException) {
                return true;
            }
        }
        return false;
    }

    private SourceResult notChecked(Source source, Indicator indicator, NotCheckedReason reason) {
        return new SourceResult(
                UUID.randomUUID(),
                source.name(),
                indicator,
                Outcome.NOT_CHECKED,
                reason,
                null,
                source.link(indicator),
                null,
                clock.instant().truncatedTo(ChronoUnit.MICROS));
    }

    /** @param readings the Lookup's readings, in the same order as its Source Results */
    private void keep(UUID analystId, Lookup lookup, List<Reading> readings) {
        jdbc.sql("""
                        insert into lookup (id, analyst_id, indicator, indicator_type, verdict, partial, looked_up_at)
                        values (:id, :analystId, :indicator, :indicatorType, :verdict, :partial, :lookedUpAt)
                        """)
                .param("id", lookup.id())
                .param("analystId", analystId)
                .param("indicator", lookup.indicator())
                .param("indicatorType", lookup.indicatorType().name())
                .param("verdict", lookup.verdict().name())
                .param("partial", lookup.partial())
                .param("lookedUpAt", lookup.lookedUpAt().atOffset(ZoneOffset.UTC))
                .update();
        for (var i = 0; i < readings.size(); i++) {
            var reading = readings.get(i);
            var reused = lookup.sourceResults().get(i).reused();
            // A reused Source Result is already kept, and is never changed
            if (!reused) {
                sourceResults.add(reading.result());
            }
            jdbc.sql("""
                            insert into lookup_source_result
                                (lookup_id, source_result_id, signal, explanation, reused, position)
                            values (:lookupId, :sourceResultId, :signal, :explanation, :reused, :position)
                            """)
                    .param("lookupId", lookup.id())
                    .param("sourceResultId", reading.result().id())
                    .param("signal", reading.signal().name())
                    .param("explanation", reading.explanation())
                    .param("reused", reused)
                    .param("position", i)
                    .update();
        }
    }

    private static UsedSourceResult used(Reading reading, boolean reused) {
        return UsedSourceResult.of(reading.result(), reading.signal(), reused);
    }
}
