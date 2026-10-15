package io.github.mtarek7900.tid.lookup;

import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class LookupHistory {

    private final JdbcClient jdbc;

    LookupHistory(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** The Analyst's Lookups, most recent first. */
    List<LookupHistoryEntry> of(UUID analystId) {
        return jdbc.sql("""
                        select id, indicator, indicator_type, verdict, looked_up_at
                        from lookup
                        where analyst_id = :analystId
                        order by looked_up_at desc
                        """)
                .param("analystId", analystId)
                .query(LookupHistoryEntry.class)
                .list();
    }
}
