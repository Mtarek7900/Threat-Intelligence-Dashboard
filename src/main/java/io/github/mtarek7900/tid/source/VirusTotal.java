package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** The VirusTotal v3 API. It covers every Indicator Type. */
@Component
class VirusTotal implements Source {

    private static final String NAME = "VirusTotal";
    private static final String SITE = "https://www.virustotal.com/gui/";

    private final RestClient http;
    private final ObjectMapper json;
    private final Clock clock;

    VirusTotal(RestClient.Builder http, Properties properties, ObjectMapper json, Clock clock) {
        this.http = http.baseUrl(properties.baseUrl())
                .defaultHeader("x-apikey", properties.apiKey())
                .build();
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
    public SourceResult fetch(Indicator indicator) {
        var paths = Paths.of(indicator.type());
        return http.get()
                .uri("/api/v3/{collection}/{id}", paths.api(), indicator.value())
                .exchange((request, response) -> {
                    var body = new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
                    var link = SITE + paths.site() + "/" + indicator.value();
                    if (response.getStatusCode().is2xxSuccessful()) {
                        return fromAnalysis(indicator, link, body);
                    }
                    if (response.getStatusCode().isSameCodeAs(HttpStatus.NOT_FOUND) && isNotFoundError(body)) {
                        return result(indicator, Outcome.NOT_SEEN, null, link, body);
                    }
                    throw new SourceException(NAME + " answered " + response.getStatusCode());
                });
    }

    /** VirusTotal knows of an Indicator it has never analysed; that isn't Seen. */
    private SourceResult fromAnalysis(Indicator indicator, String link, String body) {
        var attributes = parse(body).path("data").path("attributes");
        if (!attributes.hasNonNull("last_analysis_date")) {
            return result(indicator, Outcome.NOT_SEEN, null, link, body);
        }
        var stats = attributes.path("last_analysis_stats");
        var flagged = stats.path("malicious").asInt();
        // The engines that gave an opinion, as VirusTotal's own "flagged by X of Y" counts them
        var total = flagged
                + stats.path("suspicious").asInt()
                + stats.path("harmless").asInt()
                + stats.path("undetected").asInt();
        var lastAnalysedAt = Instant.ofEpochSecond(attributes.get("last_analysis_date").asLong());
        return result(indicator, Outcome.SEEN, new VirusTotalFacts(flagged, total, lastAnalysedAt), link, body);
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
            throw new SourceException(NAME + " answered with malformed JSON", e);
        }
    }

    private SourceResult result(Indicator indicator, Outcome outcome, SourceFacts facts, String link, String body) {
        // PostgreSQL keeps microseconds, so truncate to return what a later read will see
        var fetchedAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        return new SourceResult(UUID.randomUUID(), NAME, indicator, outcome, facts, link, body, fetchedAt);
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
