package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.Indicator;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

@Service
class LookupService {

    private final JdbcClient jdbc;
    private final Clock clock;

    LookupService(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /** Makes and keeps a Lookup. No Sources exist yet, so nobody has Seen the Indicator. */
    Lookup lookUp(UUID analystId, Indicator indicator) {
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var lookedUpAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        var lookup = new Lookup(UUID.randomUUID(), indicator.value(), indicator.type(), Verdict.UNKNOWN, lookedUpAt);
        jdbc.sql("""
                        insert into lookup (id, analyst_id, indicator, indicator_type, verdict, partial, looked_up_at)
                        values (:id, :analystId, :indicator, :indicatorType, :verdict, false, :lookedUpAt)
                        """)
                .param("id", lookup.id())
                .param("analystId", analystId)
                .param("indicator", lookup.indicator())
                .param("indicatorType", lookup.indicatorType().name())
                .param("verdict", lookup.verdict().name())
                .param("lookedUpAt", lookedUpAt.atOffset(ZoneOffset.UTC))
                .update();
        return lookup;
    }
}
