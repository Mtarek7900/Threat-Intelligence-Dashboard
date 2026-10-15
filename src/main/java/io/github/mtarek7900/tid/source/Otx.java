package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.net.InternetDomainName;
import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.StreamSupport;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/** The AlienVault OTX v1 API. It covers every Indicator Type and is a Corroborating Source. */
// Sources are asked, explained and shown in this order: VirusTotal, AbuseIPDB, then AlienVault OTX
@Component
@Order(3)
class Otx implements Source {

    private static final String NAME = "AlienVault OTX";
    private static final String SITE = "https://otx.alienvault.com/indicator/";

    private final SourceApi api;

    Otx(SourceApis apis, Properties properties) {
        this.api = apis.of(NAME, "OTX_API_KEY", properties.apiKey(), http -> http
                .baseUrl(properties.baseUrl())
                .defaultHeader("X-OTX-API-KEY", properties.apiKey()));
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
        return SITE + Section.of(indicator).site() + "/" + indicator.value();
    }

    @Override
    public SourceResult fetch(Indicator indicator) {
        var answer = api.get(uri -> uri.path("/api/v1/indicators/{section}/{id}/general")
                .build(Section.of(indicator).api(), indicator.value()));
        if (answer.ok()) {
            return fromGeneral(indicator, answer.body());
        }
        throw api.unusable(answer);
    }

    /** OTX answers for every valid Indicator; one no pulse mentions isn't Seen. */
    private SourceResult fromGeneral(Indicator indicator, String body) {
        var pulseInfo = api.parse(body).path("pulse_info");
        if (!pulseInfo.isObject()) {
            throw new SourceException(NotCheckedReason.SOURCE_ERROR, NAME + " answered without pulse info");
        }
        var pulseCount = pulseInfo.path("count").asInt();
        if (pulseCount == 0) {
            return api.result(indicator, Outcome.NOT_SEEN, null, link(indicator), body);
        }
        var pulses = StreamSupport.stream(pulseInfo.path("pulses").spliterator(), false)
                .map(pulse -> new OtxFacts.Pulse(
                        pulse.path("name").asText(),
                        StreamSupport.stream(pulse.path("tags").spliterator(), false)
                                .map(JsonNode::asText)
                                .toList()))
                .toList();
        return api.result(indicator, Outcome.SEEN, new OtxFacts(pulseCount, pulses), link(indicator), body);
    }

    /** Where OTX keeps an Indicator, in its API and on its site. */
    private record Section(String api, String site) {

        static Section of(Indicator indicator) {
            return switch (indicator.type()) {
                case IP_ADDRESS -> indicator.value().contains(":") ? new Section("IPv6", "ip") : new Section("IPv4", "ip");
                case DOMAIN -> isHostname(indicator.value()) ? new Section("hostname", "hostname") : new Section("domain", "domain");
                case FILE_HASH -> new Section("file", "file");
            };
        }

        /**
         * OTX keeps a registered domain, like {@code example.co.uk}, apart from a hostname under one,
         * like {@code www.example.com}, and reports no pulses for one asked about as the other.
         */
        private static boolean isHostname(String domain) {
            try {
                var name = InternetDomainName.from(domain);
                return name.isUnderRegistrySuffix() && !name.isTopDomainUnderRegistrySuffix();
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
    }

    /** {@code tid.sources.otx} in application.yml. */
    @ConfigurationProperties("tid.sources.otx")
    record Properties(String baseUrl, String apiKey) {}
}
