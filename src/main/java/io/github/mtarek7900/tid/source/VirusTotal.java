package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** The VirusTotal v3 API. It covers every Indicator Type. */
@Component
class VirusTotal implements Source {

    private static final String NAME = "VirusTotal";
    private static final String SITE = "https://www.virustotal.com/gui/";

    private final RestClient http;
    private final boolean hasApiKey;
    private final ObjectMapper json;
    private final Clock clock;

    VirusTotal(
            RestClient.Builder http,
            Properties properties,
            SourcesProperties sources,
            ObjectMapper json,
            Clock clock) {
        // A call the Lookup has stopped waiting for must not hold its connection open forever
        var requests = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(sources.timeout()).build());
        requests.setReadTimeout(sources.timeout());
        this.http = http.requestFactory(requests)
                .baseUrl(properties.baseUrl())
                .defaultHeader("x-apikey", properties.apiKey())
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
        return EnumSet.allOf(IndicatorType.class);
    }

    @Override
    public String link(Indicator indicator) {
        return SITE + Paths.of(indicator.type()).site() + "/" + indicator.value();
    }

    @Override
    public SourceResult fetch(Indicator indicator) {
        if (!hasApiKey) {
            throw new SourceException(NotCheckedReason.MISSING_API_KEY, "VIRUSTOTAL_API_KEY isn't set");
        }
        return http.get()
                .uri("/api/v3/{collection}/{id}", Paths.of(indicator.type()).api(), indicator.value())
                .exchange((request, response) -> {
                    var body = new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
                    var status = response.getStatusCode();
                    if (status.is2xxSuccessful()) {
                        return fromAnalysis(indicator, body);
                    }
                    if (status.isSameCodeAs(HttpStatus.NOT_FOUND) && isNotFoundError(body)) {
                        return result(indicator, Outcome.NOT_SEEN, null, body);
                    }
                    if (status.isSameCodeAs(HttpStatus.TOO_MANY_REQUESTS)) {
                        throw new SourceException(NotCheckedReason.RATE_LIMITED, NAME + " answered " + status);
                    }
                    throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered " + status);
                });
    }

    /** VirusTotal knows of an Indicator it has never analysed; that isn't Seen. */
    private SourceResult fromAnalysis(Indicator indicator, String body) {
        var attributes = parse(body).path("data").path("attributes");
        if (!attributes.hasNonNull("last_analysis_date")) {
            return result(indicator, Outcome.NOT_SEEN, null, body);
        }
        var stats = attributes.path("last_analysis_stats");
        var flagged = stats.path("malicious").asInt();
        // The engines that gave an opinion, as VirusTotal's own "flagged by X of Y" counts them
        var total = flagged
                + stats.path("suspicious").asInt()
                + stats.path("harmless").asInt()
                + stats.path("undetected").asInt();
        var lastAnalysedAt = Instant.ofEpochSecond(attributes.get("last_analysis_date").asLong());
        return result(indicator, Outcome.SEEN, new VirusTotalFacts(flagged, total, lastAnalysedAt), body);
    }

    private boolean isNotFoundError(String body) {
        try {
            return "NotFoundError".equals(json.readTree(body).path("error").path("code").asText());
        } catch (JsonProcessingException e) {
            return false;
        }
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

    /** Where VirusTotal keeps each Indicator Type, in its API and on its site. */
    private record Paths(String api, String site) {

        static Paths of(IndicatorType type) {
            return switch (type) {
                case IP_ADDRESS -> new Paths("ip_addresses", "ip-address");
                case DOMAIN -> new Paths("domains", "domain");
                case FILE_HASH -> new Paths("files", "file");
            };
        }
    }

    /** {@code tid.sources.virustotal} in application.yml. */
    @ConfigurationProperties("tid.sources.virustotal")
    record Properties(String baseUrl, String apiKey) {}
}
