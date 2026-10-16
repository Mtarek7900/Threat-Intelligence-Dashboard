package io.github.mtarek7900.tid.source;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.util.EnumSet;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** The AbuseIPDB v2 API. It covers IP addresses only. */
// Sources are asked, explained and shown in this order: VirusTotal, AbuseIPDB, then AlienVault OTX
@Component
@Order(2)
class AbuseIpdb implements Source {

    private static final String NAME = "AbuseIPDB";
    // How far back AbuseIPDB looks for reports; 90 days is its own default
    private static final int MAX_AGE_IN_DAYS = 90;

    private final SourceApi api;

    AbuseIpdb(SourceApis apis, Properties properties) {
        this.api = apis.of(NAME, "ABUSEIPDB_API_KEY", properties.apiKey(), properties.dailyQuota(), http -> http
                .baseUrl(properties.baseUrl())
                .defaultHeader("Key", properties.apiKey())
                .defaultHeader("Accept", "application/json"));
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
        var answer = api.get(uri -> uri.path("/api/v2/check")
                .queryParam("ipAddress", indicator.value())
                .queryParam("maxAgeInDays", MAX_AGE_IN_DAYS)
                .build());
        if (answer.ok()) {
            return fromCheck(indicator, answer.body());
        }
        throw api.unusable(answer);
    }

    /** AbuseIPDB answers for every public IP address; one nobody has reported isn't Seen. */
    private SourceResult fromCheck(Indicator indicator, String body) {
        var data = api.parse(body).path("data");
        if (!data.isObject()) {
            throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered without a report");
        }
        var totalReports = data.path("totalReports").asInt();
        if (totalReports == 0) {
            return api.result(indicator, Outcome.NOT_SEEN, null, link(indicator), body);
        }
        var facts = new AbuseIpdbFacts(
                data.path("abuseConfidenceScore").asInt(),
                totalReports,
                data.path("countryCode").asText(null),
                data.path("isp").asText(null));
        return api.result(indicator, Outcome.SEEN, facts, link(indicator), body);
    }

    /** {@code tid.sources.abuseipdb} in application.yml. */
    @ConfigurationProperties("tid.sources.abuseipdb")
    record Properties(String baseUrl, String apiKey, int dailyQuota) {}
}
