package io.github.mtarek7900.tid.source;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/** The VirusTotal v3 API. It covers every Indicator Type. */
// Sources are asked, explained and shown in this order: VirusTotal, AbuseIPDB, then AlienVault OTX
@Component
@Order(1)
class VirusTotal implements Source {

    private static final String NAME = "VirusTotal";
    private static final String SITE = "https://www.virustotal.com/gui/";

    private final SourceApi api;

    VirusTotal(SourceApis apis, Properties properties) {
        this.api = apis.of(NAME, "VIRUSTOTAL_API_KEY", properties.apiKey(), properties.dailyQuota(), http -> http
                .baseUrl(properties.baseUrl())
                .defaultHeader("x-apikey", properties.apiKey()));
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
        var answer = api.get(uri -> uri.path("/api/v3/{collection}/{id}")
                .build(Paths.of(indicator.type()).api(), indicator.value()));
        if (answer.ok()) {
            return fromAnalysis(indicator, answer.body());
        }
        if (answer.status().isSameCodeAs(HttpStatus.NOT_FOUND) && isNotFoundError(answer.body())) {
            return api.result(indicator, Outcome.NOT_SEEN, null, link(indicator), answer.body());
        }
        throw api.unusable(answer);
    }

    /** VirusTotal knows of an Indicator it has never analysed; that isn't Seen. */
    private SourceResult fromAnalysis(Indicator indicator, String body) {
        var attributes = api.parse(body).path("data").path("attributes");
        if (!attributes.hasNonNull("last_analysis_date")) {
            return api.result(indicator, Outcome.NOT_SEEN, null, link(indicator), body);
        }
        var stats = attributes.path("last_analysis_stats");
        var flagged = stats.path("malicious").asInt();
        // The engines that gave an opinion, as VirusTotal's own "flagged by X of Y" counts them
        var total = flagged
                + stats.path("suspicious").asInt()
                + stats.path("harmless").asInt()
                + stats.path("undetected").asInt();
        var lastAnalysedAt = Instant.ofEpochSecond(attributes.get("last_analysis_date").asLong());
        return api.result(
                indicator, Outcome.SEEN, new VirusTotalFacts(flagged, total, lastAnalysedAt), link(indicator), body);
    }

    private boolean isNotFoundError(String body) {
        return "NotFoundError".equals(api.parse(body).path("error").path("code").asText());
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
    record Properties(String baseUrl, String apiKey, int dailyQuota) {}
}
