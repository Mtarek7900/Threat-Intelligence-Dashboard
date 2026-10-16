package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mtarek7900.tid.indicator.Indicator;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Every Source Result ever fetched. Append-only: there is no way to change or remove one. */
@Repository
public class SourceResults {

    private final JdbcClient jdbc;
    private final ObjectMapper json;

    SourceResults(JdbcClient jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public void add(SourceResult result) {
        jdbc.sql("""
                        insert into source_result
                            (id, source, indicator, indicator_type, outcome, not_checked_reason, facts, link,
                             raw_response, fetched_at)
                        values
                            (:id, :source, :indicator, :indicatorType, :outcome, :notCheckedReason,
                             cast(:facts as jsonb), :link, :rawResponse, :fetchedAt)
                        """)
                .param("id", result.id())
                .param("source", result.source())
                .param("indicator", result.indicator().value())
                .param("indicatorType", result.indicator().type().name())
                .param("outcome", result.outcome().name())
                .param("notCheckedReason", result.notCheckedReason() == null ? null : result.notCheckedReason().name())
                .param("facts", result.facts() == null ? null : toJson(result.facts()))
                .param("link", result.link())
                .param("rawResponse", result.rawResponse())
                .param("fetchedAt", result.fetchedAt().atOffset(ZoneOffset.UTC))
                .update();
    }

    /**
     * Each Source's newest Seen or Not Seen Source Result about the Indicator fetched after
     * {@code since}, by Source name. A Not Checked one is never reusable: the Source didn't answer.
     */
    public Map<String, SourceResult> newestReusable(Indicator indicator, Instant since) {
        return jdbc.sql("""
                        select distinct on (source)
                            id, source, outcome, not_checked_reason, facts, link, raw_response, fetched_at
                        from source_result
                        where indicator = :indicator
                          and indicator_type = :indicatorType
                          and outcome in ('SEEN', 'NOT_SEEN')
                          and fetched_at > :since
                        order by source, fetched_at desc
                        """)
                .param("indicator", indicator.value())
                .param("indicatorType", indicator.type().name())
                .param("since", since.atOffset(ZoneOffset.UTC))
                .query((row, rowNumber) -> fromRow(row, indicator))
                .list()
                .stream()
                .collect(Collectors.toMap(SourceResult::source, Function.identity()));
    }

    private SourceResult fromRow(ResultSet row, Indicator indicator) throws SQLException {
        var notCheckedReason = row.getString("not_checked_reason");
        var facts = row.getString("facts");
        return new SourceResult(
                row.getObject("id", UUID.class),
                row.getString("source"),
                indicator,
                Outcome.valueOf(row.getString("outcome")),
                notCheckedReason == null ? null : NotCheckedReason.valueOf(notCheckedReason),
                facts == null ? null : fromJson(facts),
                row.getString("link"),
                row.getString("raw_response"),
                row.getObject("fetched_at", OffsetDateTime.class).toInstant());
    }

    private SourceFacts fromJson(String facts) {
        try {
            return json.readValue(facts, SourceFacts.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Couldn't read stored facts " + facts, e);
        }
    }

    private String toJson(SourceFacts facts) {
        try {
            return json.writeValueAsString(facts);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Couldn't store " + facts, e);
        }
    }
}
