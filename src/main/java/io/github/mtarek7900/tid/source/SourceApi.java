package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mtarek7900.tid.indicator.Indicator;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriBuilder;

/**
 * One Source's API, as its adapter asks it. It isn't asked without an API key or once it has been
 * asked its daily limit, and an answer the adapter can't use becomes a Not Checked Source Result. Made by {@link SourceApis}.
 */
final class SourceApi {

    /** What the Source answered, read in full. */
    record Answer(HttpStatusCode status, String body) {

        boolean ok() {
            return status.is2xxSuccessful();
        }
    }

    private final String source;
    private final String apiKeyVariable;
    private final boolean hasApiKey;
    private final RestClient http;
    private final ObjectMapper json;
    private final BooleanSupplier countCall;
    private final Clock clock;

    /** @param countCall counts a call about to be sent, or says the daily limit is reached */
    SourceApi(
            String source,
            String apiKeyVariable,
            String apiKey,
            RestClient http,
            ObjectMapper json,
            BooleanSupplier countCall,
            Clock clock) {
        this.source = source;
        this.apiKeyVariable = apiKeyVariable;
        this.hasApiKey = apiKey != null && !apiKey.isBlank();
        this.http = http;
        this.json = json;
        this.countCall = countCall;
        this.clock = clock;
    }

    Answer get(Function<UriBuilder, URI> uri) {
        if (!hasApiKey) {
            throw new SourceException(NotCheckedReason.MISSING_API_KEY, apiKeyVariable + " isn't set");
        }
        // Counted when sent, not when answered: the Source counts a call it answers too late or with an error
        if (!countCall.getAsBoolean()) {
            throw new SourceException(NotCheckedReason.DAILY_LIMIT_REACHED, source + " has been asked its daily limit");
        }
        return http.get()
                .uri(uri)
                .exchange((request, response) -> new Answer(
                        response.getStatusCode(),
                        new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }

    /** The Source is limiting how often it can be asked, or answered with an error. */
    SourceException unusable(Answer answer) {
        var reason = answer.status().isSameCodeAs(HttpStatus.TOO_MANY_REQUESTS)
                ? NotCheckedReason.RATE_LIMITED
                : NotCheckedReason.SOURCE_ERROR;
        return new SourceException(reason, source + " answered " + answer.status());
    }

    JsonNode parse(String body) {
        try {
            return json.readTree(body);
        } catch (JsonProcessingException e) {
            throw new SourceException(NotCheckedReason.SOURCE_ERROR, source + " answered with malformed JSON", e);
        }
    }

    SourceResult result(Indicator indicator, Outcome outcome, SourceFacts facts, String link, String body) {
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var fetchedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        return new SourceResult(UUID.randomUUID(), source, indicator, outcome, null, facts, link, body, fetchedAt);
    }
}
