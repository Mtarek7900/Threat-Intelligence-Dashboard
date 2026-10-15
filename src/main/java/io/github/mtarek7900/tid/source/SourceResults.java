package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.ZoneOffset;
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

    private String toJson(SourceFacts facts) {
        try {
            return json.writeValueAsString(facts);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Couldn't store " + facts, e);
        }
    }
}
