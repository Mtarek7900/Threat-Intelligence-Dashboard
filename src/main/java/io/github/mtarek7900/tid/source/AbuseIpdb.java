package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** The AbuseIPDB v2 API. It covers IP addresses only. */
// Sources are asked, explained and shown in this order: VirusTotal first, then AbuseIPDB
@Component
@Order(2)
class AbuseIpdb implements Source {

    private static final String NAME = "AbuseIPDB";
    // How far back AbuseIPDB looks for reports; 90 days is its own default
    private static final int MAX_AGE_IN_DAYS = 90;

    private final RestClient http;
    private final boolean hasApiKey;
    private final ObjectMapper json;
    private final Clock clock;

    AbuseIpdb(
            RestClient.Builder http,
            Properties properties,
            SourcesProperties sources,
            ObjectMapper json,
            Clock clock) {
        this.http = SourceHttp.withTimeouts(http, sources.timeout())
                .baseUrl(properties.baseUrl())
                .defaultHeader("Key", properties.apiKey())
                .defaultHeader("Accept", "application/json")
                .build();
        this.hasApiKey = properties.apiKey() != null && !properties.apiKey().isBlank();
        this.json = json;
        this.clock = clock;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public Set<IndicatorType> indicatorTypes() {
        return EnumSet.of(IndicatorType.IP_ADDRESS);
    }

    @Override
    public String link(Indicator indicator) {
        return "https://www.abuseipdb.com/check/" + indicator.value();
    }

    @Override
    public SourceResult fetch(Indicator indicator) {
        if (!hasApiKey) {
            throw new SourceException(NotCheckedReason.MISSING_API_KEY, "ABUSEIPDB_API_KEY isn't set");
        }
        return http.get()
                .uri(uri -> uri.path("/api/v2/check")
                        .queryParam("ipAddress", indicator.value())
                        .queryParam("maxAgeInDays", MAX_AGE_IN_DAYS)
                        .build())
                .exchange((request, response) -> {
                    var body = new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
                    var status = response.getStatusCode();
                    if (status.is2xxSuccessful()) {
                        return fromCheck(indicator, body);
                    }
                    if (status.isSameCodeAs(HttpStatus.TOO_MANY_REQUESTS)) {
                        throw new SourceException(NotCheckedReason.RATE_LIMITED, NAME + " answered " + status);
                    }
                    throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered " + status);
                });
    }

    /** AbuseIPDB answers for every public IP address; one nobody has reported isn't Seen. */
    private SourceResult fromCheck(Indicator indicator, String body) {
        var data = parse(body).path("data");
        if (!data.isObject()) {
            throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered without a report");
        }
        var totalReports = data.path("totalReports").asInt();
        if (totalReports == 0) {
            return result(indicator, Outcome.NOT_SEEN, null, body);
        }
        var facts = new AbuseIpdbFacts(
                data.path("abuseConfidenceScore").asInt(),
                totalReports,
                data.path("countryCode").asText(null),
                data.path("isp").asText(null));
        return result(indicator, Outcome.SEEN, facts, body);
    }

    private JsonNode parse(String body) {
        try {
            return json.readTree(body);
        } catch (JsonProcessingException e) {
            throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered with malformed JSON", e);
        }
    }

    private SourceResult result(Indicator indicator, Outcome outcome, SourceFacts facts, String body) {
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var fetchedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        return new SourceResult(
                UUID.randomUUID(), NAME, indicator, outcome, null, facts, link(indicator), body, fetchedAt);
    }

    /** {@code tid.sources.abuseipdb} in application.yml. */
    @ConfigurationProperties("tid.sources.abuseipdb")
    record Properties(String baseUrl, String apiKey) {}
}
