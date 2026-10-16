package io.github.mtarek7900.tid.source;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** How many times each Source has been asked today. A day starts at midnight UTC, as the Sources count theirs. */
@Repository
class DailyCalls {

    private final JdbcClient jdbc;
    private final Clock clock;

    DailyCalls(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /**
     * Counts one more call to the Source today, unless it has already been asked {@code limit} times.
     *
     * @return whether the call was counted and so may be sent
     */
    boolean count(String source, int limit) {
        if (limit <= 0) {
            return false;
        }
        // One statement, so Lookups at the same time can't both take the last call
        return jdbc.sql("""
                        insert into source_daily_calls (source, day, calls)
                        values (:source, :day, 1)
                        on conflict (source, day) do update set calls = source_daily_calls.calls + 1
                        where source_daily_calls.calls < :limit
                        returning calls
                        """)
                .param("source", source)
                .param("day", LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC))
                .param("limit", limit)
                .query(Integer.class)
                .optional()
                .isPresent();
    }
}
